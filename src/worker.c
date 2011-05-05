/*
 * worker.c
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#include <alloca.h>
#include <ev.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib.h"
#include "maxfd.h"
#include "pyenv.h"
#include "rbuf.h"
#include "session.h"
#include "worker.h"


static void worker_exited_cb(EV_P_ ev_child *w, int revents);

static void worker_write_stdin_cb(EV_P_ ev_io *w, int revents);
static void worker_read_stdout_cb(EV_P_ ev_io *w, int revents);
static void worker_read_stderr_cb(EV_P_ ev_io *w, int revents);
static void worker_write_msgin_cb(EV_P_ ev_io *w, int revents);
static void worker_read_msgout_cb(EV_P_ ev_io *w, int revents);

static inline void worker_write_input_cb(EV_P_ ev_io *w, int revents,
                                         struct worker *worker,
                                         struct writeq *writeq,
                                         enum msg_type type);
static inline void worker_read_output_cb(EV_P_ ev_io *w, int revents,
                                         struct worker *worker,
                                         enum msg_type type);

#if WORKER_TIMINGS
static uint64_t worker_start_time;
static uint64_t worker_start_calls;
#endif



struct worker *
worker_start(EV_P_ struct session *session)
{
    struct worker *w;
    pid_t pid;
    int stdin_fds [2] = {-1, -1};
    int stdout_fds[2] = {-1, -1};
    int stderr_fds[2] = {-1, -1};
    int msgin_fds [2] = {-1, -1};
    int msgout_fds[2] = {-1, -1};

#if WORKER_TIMINGS
    uint64_t _start = now_us();
#endif

    if ((w = calloc(1, sizeof(*w))) == NULL) {
        goto fail;
    }
    w->session = session;
    writeq_init(&w->stdin_writeq);
    writeq_init(&w->msgin_writeq);

    if (pipe(stdin_fds ) < 0 ||
        pipe(stdout_fds) < 0 ||
        pipe(stderr_fds) < 0 ||
        pipe(msgin_fds ) < 0 ||
        pipe(msgout_fds) < 0) {
        LOG_ERRNO("pipe()");
        goto fail;
    }
    maxfd_update(stdin_fds [0]);
    maxfd_update(stdin_fds [1]);
    maxfd_update(stdout_fds[0]);
    maxfd_update(stdout_fds[1]);
    maxfd_update(stderr_fds[0]);
    maxfd_update(stderr_fds[1]);
    maxfd_update(msgin_fds [0]);
    maxfd_update(msgin_fds [1]);
    maxfd_update(msgout_fds[0]);
    maxfd_update(msgout_fds[1]);


    pid = fork();
    if (pid < 0) {
        LOG_ERRNO("fork()");
        goto fail;
    }
    if (pid == 0) {
        /* child. */
        if (dup2(stdin_fds [0], 0) < 0 ||
            dup2(stdout_fds[1], 1) < 0 ||
            dup2(stderr_fds[1], 2) < 0 ||
            dup2(msgin_fds [0], 3) < 0 ||
            dup2(msgout_fds[1], 4) < 0) {
            exit(EXIT_FAILURE);
        }
        maxfd_closeall(5);
        pyenv_child_after_fork();
        exit(EXIT_SUCCESS);
    } else {
        /* parent. */
        close(stdin_fds [0]);
        close(stdout_fds[1]);
        close(stderr_fds[1]);
        close(msgin_fds [0]);
        close(msgout_fds[1]);

        set_fd_nonblocking(stdin_fds [1]);
        set_fd_nonblocking(stdout_fds[0]);
        set_fd_nonblocking(stderr_fds[0]);
        set_fd_nonblocking(msgin_fds [1]);
        set_fd_nonblocking(msgout_fds[0]);

        ev_child_init(&w->child_watcher, worker_exited_cb, pid, 0);
        ev_child_start(EV_A_ &w->child_watcher);

        ev_io_init(&w->stdin_w , worker_write_stdin_cb, stdin_fds [1],
                   EV_WRITE);
        ev_io_init(&w->stdout_w, worker_read_stdout_cb, stdout_fds[0],
                   EV_READ);
        ev_io_init(&w->stderr_w, worker_read_stderr_cb, stderr_fds[0],
                   EV_READ);
        ev_io_init(&w->msgin_w , worker_write_msgin_cb, msgin_fds [1],
                   EV_WRITE);
        ev_io_init(&w->msgout_w, worker_read_msgout_cb, msgout_fds[0],
                   EV_READ);
        ev_io_start(EV_A_ &w->stdout_w);
        ev_io_start(EV_A_ &w->stderr_w);
        ev_io_start(EV_A_ &w->msgout_w);

        LOGF(3, "=== %d: worker started, fds=[%d, %d, %d, %d, %d]\n",
             worker_pid(w), stdin_fds[1], stdout_fds[0], stderr_fds[0],
             msgin_fds[1], msgout_fds[0]);

        w->f_alive = true;
    }
#if WORKER_TIMINGS
    worker_start_time += now_us() - _start;
    worker_start_calls++;
#endif

    return w;

 fail:
    close(stdin_fds [0]);
    close(stdin_fds [1]);
    close(stdout_fds[0]);
    close(stdout_fds[1]);
    close(stderr_fds[0]);
    close(stderr_fds[1]);
    close(msgin_fds [0]);
    close(msgin_fds [1]);
    close(msgout_fds[0]);
    close(msgout_fds[1]);
    free(w);
    return NULL;
}

void
worker_stop(EV_P_ struct worker *worker)
{
    LOGF(3, "=== %d: worker stopped\n", worker_pid(worker));

    if (worker->f_alive) {
        LOGF(1, "=== %d: worker still alive - sending SIGKILL\n",
             worker_pid(worker));
        kill(worker_pid(worker), SIGKILL);
    }
    writeq_uninit(&worker->stdin_writeq);
    writeq_uninit(&worker->msgin_writeq);
    if (ev_is_active(&worker->child_watcher)) {
        ev_child_stop(EV_A_ &worker->child_watcher);
    }
    if (ev_is_active(&worker->stdin_w)) {
        ev_io_stop(EV_A_ &worker->stdin_w);
    }
    if (ev_is_active(&worker->stdout_w)) {
        ev_io_stop(EV_A_ &worker->stdout_w);
    }
    if (ev_is_active(&worker->stderr_w)) {
        ev_io_stop(EV_A_ &worker->stderr_w);
    }
    if (ev_is_active(&worker->msgin_w)) {
        ev_io_stop(EV_A_ &worker->msgin_w);
    }
    if (ev_is_active(&worker->msgout_w)) {
        ev_io_stop(EV_A_ &worker->msgout_w);
    }
    close(worker->stdin_w.fd);
    close(worker->stdout_w.fd);
    close(worker->stderr_w.fd);
    close(worker->msgin_w.fd);
    close(worker->msgout_w.fd);
    free(worker);
}

int
worker_write_input(EV_P_ struct worker *worker, const struct msg_hdr *hdr,
                   struct rbuf *body)
{
    struct writeq *writeq;
    ev_io *write_w;

    if (hdr->type == MSG_TYPE_WORKER_STDIN) {
        writeq = &worker->stdin_writeq;
        write_w = &worker->stdin_w;
    } else {
        writeq = &worker->msgin_writeq;
        write_w = &worker->msgin_w;
    }
    if (writeq_append_rbuf(writeq, body) < 0) {
        return -1;
    }
    if (writeq_write(writeq, write_w->fd) < 0) {
        return -1;
    }
    if (writeq_is_empty(writeq)) {
        // no more writes needed - disarm writes.
        if (ev_is_active(write_w)) {
            ev_io_stop(EV_A_ write_w);
        }
    } else {
        // more writes needed, arm writes.
        if (!ev_is_active(write_w)) {
            ev_io_start(EV_A_ write_w);
        }
    }
    return 0;
}

static void
worker_exited_cb(EV_P_ ev_child *w, int revents)
{
    struct worker *worker = CONTAINER_OF(w, struct worker, child_watcher);

    LOGF(3, "=== %d: worker ended, status=%d\n", worker_pid(worker),
         w->rstatus);

    ev_child_stop(EV_A_ w);
    worker->f_alive = false;

    if (worker->session == NULL) {
        printf("WARNING: worker without session!\n");
        return;
    }

    session_on_worker_exited_cb(EV_A_ worker->session, w->rstatus);
}

static void
worker_write_stdin_cb(EV_P_ ev_io *w, int revents)
{
    struct worker *worker = CONTAINER_OF(w, struct worker, stdin_w);
    worker_write_input_cb(EV_A_ w, revents, worker, &worker->stdin_writeq,
                          MSG_TYPE_WORKER_STDIN);
}

static void
worker_read_stdout_cb(EV_P_ ev_io *w, int revents)
{
    worker_read_output_cb(EV_A_ w, revents,
                          CONTAINER_OF(w, struct worker, stdout_w),
                          MSG_TYPE_WORKER_STDOUT);
}

static void
worker_read_stderr_cb(EV_P_ ev_io *w, int revents)
{
    worker_read_output_cb(EV_A_ w, revents,
                          CONTAINER_OF(w, struct worker, stderr_w),
                          MSG_TYPE_WORKER_STDERR);
}

static void
worker_write_msgin_cb(EV_P_ ev_io *w, int revents)
{
    struct worker *worker = CONTAINER_OF(w, struct worker, msgin_w);
    worker_write_input_cb(EV_A_ w, revents, worker, &worker->msgin_writeq,
                          MSG_TYPE_WORKER_MSGIN);
}

static void
worker_read_msgout_cb(EV_P_ ev_io *w, int revents)
{
    worker_read_output_cb(EV_A_ w, revents,
                          CONTAINER_OF(w, struct worker, msgout_w),
                          MSG_TYPE_WORKER_MSGOUT);
}

static inline void
worker_write_input_cb(EV_P_ ev_io *w, int revents, struct worker *worker,
                   struct writeq *writeq, enum msg_type type)
{
    int rc;

    if (worker->session == NULL) {
        printf("ERROR: worker without session!\n");
        worker_stop(EV_A_ worker);
        return;
    }

    if ((revents & EV_ERROR)) {
        goto err;
    }

    rc = writeq_write(writeq, w->fd);
    if (rc < 0) {
        goto err;
    } else if (rc > 0) {
        /* disarm writes. */
        ev_io_stop(EV_A_ w);
        return;
    }
    return;

 err:
    DEBUGF(0, "WARNING: worker pid %d input pipe fd=%d error\n",
           worker_pid(worker), w->fd);
    ev_io_stop(EV_A_ w);
    session_on_worker_pipe_err_cb(EV_A_ worker->session, type);
}

struct worker_read_ctx {
    struct session *session;
    enum msg_type type;
};

static void
worker_rbuf_read_cb(EV_P_ void *ctx, struct rbuf **rbufs, int nrbufs,
                    uint16_t nbytes)
{
    struct worker_read_ctx *read_ctx = ctx;
    session_on_worker_output_cb(EV_A_ read_ctx->session, rbufs, nrbufs,
                                nbytes, read_ctx->type);
}

static inline void
worker_read_output_cb(EV_P_ ev_io *w, int revents, struct worker *worker,
                      enum msg_type type)
{
    struct worker_read_ctx ctx = {
        .session = worker->session,
        .type = type,
    };
    int rc;

    if (worker->session == NULL) {
        printf("ERROR: worker without session!\n");
        worker_stop(EV_A_ worker);
        return;
    }

    if ((revents & EV_ERROR)) {
        goto err;
    }

    rc = rbuf_read_chunks(EV_A_ w->fd, worker_rbuf_read_cb, &ctx);
    if (rc < 0) {
        goto err;
    } else if (rc > 0) {
        /* EOF - disarm reads. */
        ev_io_stop(EV_A_ w);
//        session_on_worker_output_cb(EV_A_ worker->session, NULL, 0, 0, type);
    }
    return;

 err:
    DEBUGF(0, "WARNING: worker pid %d output pipe fd=%d error\n",
           worker_pid(worker), w->fd);
    ev_io_stop(EV_A_ w);
    session_on_worker_pipe_err_cb(EV_A_ worker->session, type);
}
