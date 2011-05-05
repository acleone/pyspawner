/*
 * pyspawner-slap.c
 *
 *  Created on: Apr 4, 2011
 *      Author: alex
 */

#include <ev.h>
#include <inttypes.h>
#include <pthread.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "def.h"
#include "auth.h"
#include "lib.h"
#include "msg.h"
#include "queue.h"
#include "writeq.h"

struct conn;

typedef bool (*when_seen_cb_t)(EV_P_ struct conn *conn,
                               const struct msg_hdr *hdr, struct rbuf *body);

struct expected_msg {
    TAILQ_ENTRY(expected_msg) q_entry;
    enum msg_type type;
    int sid; // -1 for anything
    int len; // -1 for anything
    const char *body; // if not NULL, check len bytes of body.
    when_seen_cb_t cb;
};

struct conn {
    ev_io read_watcher;
    ev_io write_watcher;
    struct msg_rx msg_rx;
    struct writeq writeq;
    TAILQ_HEAD(, expected_msg) expected_q;
    struct thread_ctx *thread_ctx;
    int nexecs;
    bool f_started : 1;
    bool f_in_session : 1;
};

struct thread_ctx {
    ev_io sigint_watcher;
    ev_io start_watcher;
    uint64_t start_time;
    int nconnections_done;
    int nconnections_ready;
    int ti;
    struct conn connections[0];
    /* array of conn_ctx follows */
};

static int sigint_pipe[2];
static int start_pipe[2]; /**< readable when the threads should start. */
static int nthreads;
static int nconnections;
static int nexecs;
static volatile int nthreads_ready;
static struct sockaddr_storage connect_addr_storage;
static struct sockaddr * const connect_addr =
                                     (struct sockaddr *)&connect_addr_storage;
static socklen_t connect_addrlen;


static inline int
conn_fd(struct conn *conn)
{
    return conn->read_watcher.fd;
}

static inline int
conn_writeq_hdr(struct conn *conn, uint8_t sid, uint16_t len,
                enum msg_type type)
{
    struct msg_hdr hdr = {
        .type = type,
        .sid = sid,
        .flags = { .byte = 0 },
        .len = len,
    };
    uint8_t hdr_buf[MSG_HDR_LEN];
    msg_hdr_to_buf(&hdr, hdr_buf);
    return writeq_append_copy(&conn->writeq, hdr_buf, MSG_HDR_LEN);
}

static inline int
conn_writeq_msg_copy(struct conn *conn, const void *buf,
                     uint16_t len, int sid, enum msg_type type)
{
    if (conn_writeq_hdr(conn, sid, len, type) < 0) {
        return -1;
    }
    return writeq_append_copy(&conn->writeq, buf, len);
}

static inline int
conn_writeq_msg_ptr(struct conn *conn, const void *ptr,
                    uint16_t len, int sid, enum msg_type type)
{
    if (conn_writeq_hdr(conn, sid, len, type) < 0) {
        return -1;
    }
    return writeq_append_ptr(&conn->writeq, ptr, len);
}

static inline void
conn_try_write_unarmed(EV_P_ struct conn *conn)
{
    int rc;

    EXIT_ON_NEG(rc = writeq_write(&conn->writeq, conn_fd(conn)));
    if (!writeq_is_empty(&conn->writeq)) {
        // more writes necessary - arm writes.
        if (!ev_is_active(&conn->write_watcher)) {
            ev_io_start(EV_A_ &conn->write_watcher);
        }
    }
}

static inline void
conn_add_expected_msg(struct conn *conn, enum msg_type type, int sid,
                      int len, const void *body, when_seen_cb_t cb)
{
    struct expected_msg *e;
    EXIT_ON_NULL(e = malloc(sizeof(*e)));
    e->type = type;
    e->sid = sid;
    e->len = len;
    e->body = body;
    e->cb = cb;
    TAILQ_INSERT_TAIL(&conn->expected_q, e, q_entry);
    LOGF(11, "%d Adding wait for msg type=%d, sid=%d, len=%d\n",
         conn_fd(conn), type, sid, len);
}

static void
conn_start_exec_cycle(EV_P_ struct conn *conn)
{
    if (!conn->f_in_session) {
        conn->f_in_session = true;

        EXIT_ON_NEG(conn_writeq_hdr(conn, 1, 0, MSG_TYPE_START_SESSION));
        conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 1, 4, NULL, NULL);

        EXIT_ON_NEG(conn_writeq_hdr(conn, 2, 0, MSG_TYPE_START_WORKER));
        conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 2, 4, NULL, NULL);
    }

    const char *exec = "{\"t\": \"exec\", \"code\": \"print 2+2\"}";
    /* strlen + 1 because we want to send the null byte delimiter. */
    EXIT_ON_NEG(conn_writeq_msg_ptr(conn, exec, strlen(exec) + 1, 3,
                                    MSG_TYPE_WORKER_MSGIN));
    conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 3, 0, NULL, NULL);

    const char *out4n = "4\n";
    conn_add_expected_msg(conn, MSG_TYPE_WORKER_STDOUT, 0, strlen(out4n),
                          out4n, NULL);

    const char *done = "{\"t\": \"done\"}";
    conn_add_expected_msg(conn, MSG_TYPE_WORKER_MSGOUT, 0, strlen(done) + 1,
                          done, NULL);

    conn->nexecs++;
}

static inline void
thread_conn_done(EV_P_ struct thread_ctx *thread_ctx, struct conn *conn)
{
    thread_ctx->nconnections_done++;
    LOGF(9, "--- [%d] conns done: %d / %d\n", thread_ctx->ti,
         thread_ctx->nconnections_done, nconnections);
    if (thread_ctx->nconnections_done >= nconnections) {
        ev_break(EV_A_ EVBREAK_ALL);
    }
}

static bool
conn_session_left_cb(EV_P_ struct conn *conn, const struct msg_hdr *hdr,
                     struct rbuf *body)
{
    ev_io_stop(EV_A_ &conn->read_watcher);
    thread_conn_done(EV_A_ conn->thread_ctx, conn);
    return true;
}

static bool
conn_leave_session_cb(EV_P_ struct conn *conn, const struct msg_hdr *hdr,
                      struct rbuf *body)
{
    if (!TAILQ_EMPTY(&conn->expected_q)) {
        return true;
    }
    EXIT_ON_NEG(conn_writeq_hdr(conn, 6, 0, MSG_TYPE_LEAVE_SESSION));
    conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 6, 0, NULL,
                          conn_session_left_cb);
    return true;
}

static void
conn_shutdown_worker(EV_P_ struct conn *conn)
{
    LOGF(10, "%d Shutting down worker\n", conn_fd(conn));

    const char *sdown = "{\"t\": \"shutdown\"}";
    EXIT_ON_NEG(conn_writeq_msg_ptr(conn, sdown, strlen(sdown) + 1, 4,
                                    MSG_TYPE_WORKER_MSGIN));
    conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 4, 0, NULL,
                          conn_leave_session_cb);

    const char *exit0 = "\0\0\0\0";
    conn_add_expected_msg(conn, MSG_TYPE_WORKER_EXITED, 0, 4, exit0,
                          conn_leave_session_cb);
}

static int
conn_got_msg(EV_P_ struct conn *conn, const struct msg_hdr *hdr,
             struct rbuf *body)
{
    LOGIF(9) {
        printf("> %d ", conn_fd(conn));
        print_msg_hdr(stdout, hdr);
        printf("\n");
        LOGIF(12) {
            printf("    ");
            print_repr(stdout, body->data, body->len, true);
            printf("\n");
        }
    }
    struct expected_msg *m = NULL;
    TAILQ_FOREACH(m, &conn->expected_q, q_entry) {
        if (m->type != hdr->type) {
            continue;
        }
        if (m->sid != hdr->sid) {
            continue;
        }
        if (m->len >= 0 && m->len != hdr->len) {
            continue;
        }
        if (m->body != NULL && memcmp(m->body, body->data, hdr->len) != 0) {
            continue;
        }
        // found
        goto found;
    }
    // not found
    LOGF(0, "%d WARNING: unexpected msg: type=%d, sid=%d, body=",
         conn_fd(conn), hdr->type, hdr->sid);
    print_repr(stdout, body->data, hdr->len, true);
    LOGF(0, "\n");
    return 0;
 found:
    TAILQ_REMOVE(&conn->expected_q, m, q_entry);
    if (m->cb != NULL) {
        m->cb(EV_A_ conn, hdr, body);
    }
    free(m);
    return 0;
}

static void
conn_read_ready_cb(EV_P_ ev_io *w, int revents)
{
    struct conn *conn = CONTAINER_OF(w, struct conn, read_watcher);
    int rc;

    LOGF(9, "%d read_ready_cb()\n", conn_fd(conn));
    if ((revents & EV_ERROR)) {
        goto drop;
    }

    switch (msg_rx_read1(&conn->msg_rx, conn_fd(conn))) {
    case MSG_RX_RC_ERROR:
    case MSG_RX_RC_BAD_HDR_CHKSUM:
        goto drop;
    case MSG_RX_RC_EOF:
        LOGF(0, "WARNING: %d reads EOF.\n", conn_fd(conn));
        ev_io_stop(EV_A_ w);
        return;
    case MSG_RX_RC_NEED_MORE:
        return;
    case MSG_RX_RC_GOT_MSG:
        break;
    }
    rc = conn_got_msg(EV_A_ conn, msg_rx_last_hdr(&conn->msg_rx),
                      msg_rx_last_body(&conn->msg_rx));
    msg_rx_unref_body(&conn->msg_rx);

    if (conn->f_started && TAILQ_EMPTY(&conn->expected_q)) {
        // exec cycle done.
        LOGF(11, "%d execs done: %d / %d\n", conn_fd(conn), conn->nexecs,
             nexecs);
        if (conn->nexecs >= nexecs) {
            conn_shutdown_worker(EV_A_ conn);
            conn->f_started = false;
        } else {
            conn_start_exec_cycle(EV_A_ conn);
        }
    }

    if (!writeq_is_empty(&conn->writeq) &&
            !ev_is_active(&conn->write_watcher)) {
        conn_try_write_unarmed(EV_A_ conn);
    }

    return;

 drop:
    ev_io_stop(EV_A_ w);
    printf("ERROR: %d reads dropped!\n", w->fd);
}

static void
conn_write_ready_cb(EV_P_ ev_io *w, int revents)
{
    struct conn *conn = CONTAINER_OF(w, struct conn, write_watcher);

    LOGF(9, "%d write_ready_cb()\n", conn_fd(conn));

    if ((revents & EV_ERROR)) {
        goto drop;
    }

    if (writeq_write(&conn->writeq, w->fd) < 0) {
        goto drop;
    }
    if (writeq_is_empty(&conn->writeq)) {
        // disarm writes.
        ev_io_stop(EV_A_ w);
        if (!ev_is_active(&conn->read_watcher)) {
            // not waiting for reads - drop conn?
            goto drop;
        }
    }
    return;

 drop:
    ev_io_stop(EV_A_ w);
    printf("ERROR: %d writes dropped!\n", w->fd);
}

static inline void
conn_on_start_cb(EV_P_ struct conn *conn)
{
    conn->f_started = true;
    conn_start_exec_cycle(EV_A_ conn);
    conn_try_write_unarmed(EV_A_ conn);
}

static void
thread_start_cb(EV_P_ ev_io *w, int revents)
{
    struct thread_ctx *ctx = CONTAINER_OF(w, struct thread_ctx, start_watcher);
    int i;
    LOGF(9, "--- [%d] thread_start_cb()\n", ctx->ti);
    ctx->start_time = now_us();

    for (i = 0; i < nconnections; i++) {
        struct conn *conn = &ctx->connections[i];
        conn_on_start_cb(EV_A_ conn);
    }
    ev_io_stop(EV_A_ w);
    return;
}

static bool
conn_on_auth_success_cb(EV_P_ struct conn *conn, const struct msg_hdr *hdr,
                        struct rbuf *body)
{
    struct thread_ctx *thread_ctx = conn->thread_ctx;
    thread_ctx->nconnections_ready++;
    if (thread_ctx->nconnections_ready >= nconnections) {
        atomic_inc(&nthreads_ready);
    }
    return true;
}

static bool
conn_on_nonce_cb(EV_P_ struct conn *conn, const struct msg_hdr *hdr,
                 struct rbuf *body)
{
    SHA256_CTX sctx;
    uint8_t pw_reply[SHA256_DIGEST_LENGTH + 1 + strlen("admin")];
    pw_reply[0] = 0;
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, body->data, AUTH_NONCE_LEN);
    SHA256_Update(&sctx, (const uint8_t *)"admin", strlen("admin"));
    SHA256_Final(pw_reply + strlen("admin") + 1, &sctx);
    memcpy(pw_reply, "admin", strlen("admin"));
    pw_reply[strlen("admin")] = '\0';
    EXIT_ON_NEG(conn_writeq_msg_copy(conn, pw_reply, sizeof(pw_reply), 0,
                                     MSG_TYPE_AUTH_PW_REPLY));
    conn_add_expected_msg(conn, MSG_TYPE_SUCCESS, 0, 0, NULL,
                          conn_on_auth_success_cb);
    return true;
}

static void
conn_init(EV_P_ struct conn *conn, struct thread_ctx *thread_ctx)
{
    memset(conn, 0, sizeof(*conn));
    conn->thread_ctx = thread_ctx;
    msg_rx_init(&conn->msg_rx);
    writeq_init(&conn->writeq);

    TAILQ_INIT(&conn->expected_q);
    conn_add_expected_msg(conn, MSG_TYPE_AUTH_NONCE, 0, AUTH_NONCE_LEN, NULL,
                          conn_on_nonce_cb);

    int fd;
    fd = create_connected_sock(connect_addr, connect_addrlen);
    ev_io_init(&conn->read_watcher, conn_read_ready_cb, fd, EV_READ);
    ev_io_init(&conn->write_watcher, conn_write_ready_cb, fd, EV_WRITE);
    ev_io_start(EV_A_ &conn->read_watcher);
}

static void
conn_uninit(EV_P_ struct conn *conn)
{
    struct expected_msg *e, *next_e;
    msg_rx_uninit(&conn->msg_rx);
    writeq_uninit(&conn->writeq);
    TAILQ_FOREACH_SAFE(e, &conn->expected_q, q_entry, next_e) {
        LOGF(0, "%d WARNING: still waiting for msg type=%d, sid=%d, body=",
             conn_fd(conn), e->type, e->sid);
        if (e->body != NULL) {
            print_repr(stdout, e->body, e->len, true);
        } else {
            LOGF(0, "NULL");
        }
        LOGF(0, "\n");
        free(e);
    }
    close(conn_fd(conn));
}

static void
thread_sigint_cb(EV_P_ ev_io *w, int revents)
{
    ev_break(EV_A_ EVBREAK_ALL);
}

static void *
thread_start(void *arg)
{
    // block SIGINT - only main should handle.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    EXIT_ON_PTERR(pthread_sigmask(SIG_BLOCK, &set, NULL));

    struct ev_loop *loop;
    EXIT_ON_NULL(loop = ev_loop_new(EVFLAG_AUTO));
//    printf("Using backend %u\n", ev_backend(EV_A));

    struct thread_ctx *ctx;
    int i;
    EXIT_ON_NULL(ctx = malloc(sizeof(*ctx) +
                              sizeof(struct conn) * nconnections));
    ctx->ti = (intptr_t)arg;

    for (i = 0; i < nconnections; i++) {
        struct conn * const conn = &ctx->connections[i];
        conn_init(EV_A_ conn, ctx);
    }

    ev_io_init(&ctx->sigint_watcher, thread_sigint_cb, sigint_pipe[0], EV_READ);
    ev_io_init(&ctx->start_watcher, thread_start_cb, start_pipe[0], EV_READ);
    ev_io_start(EV_A_ &ctx->sigint_watcher);
    ev_io_start(EV_A_ &ctx->start_watcher);

    ev_run(EV_A_ 0);

    uint64_t end = now_us();
    uint64_t *ret;
    EXIT_ON_NULL(ret = malloc(sizeof(*ret)));
    *ret = end - ctx->start_time;

    ev_io_stop(EV_A_ &ctx->sigint_watcher);
    ev_io_stop(EV_A_ &ctx->start_watcher);

    for (i = 0; i < nconnections; i++) {
        struct conn * const conn = &ctx->connections[i];
        conn_uninit(EV_A_ conn);
    }
    free(ctx);
    return ret;
}

static void
sigint_handler(int sig)
{
    uint8_t byte = 1;
    printf("\nCaught SIGINT, exiting...\n");
    EXIT_ON_NEG(write(sigint_pipe[1], &byte, 1));
}

static void
print_usage_and_die(int argc, char **argv)
{
    printf("Usage: %s nthreads nconns nexecs\n",
           (argc > 0)? argv[0] : "prog");
    exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    uint64_t start, end;
    pthread_t *threads = NULL;
    uint64_t *thread_times = NULL;
    int i;
    uint8_t byte = 1;

    if (argc < 4) {
        print_usage_and_die(argc, argv);
    }
    errno = 0;
    nthreads = strtol(argv[1], NULL, 10);
    nconnections = strtol(argv[2], NULL, 10);
    nexecs = strtol(argv[3], NULL, 10);
    if (errno != 0) {
        LOG_ERRNO("strtol()");
        print_usage_and_die(argc, argv);
    }

    raise_rlimit(80000);

    const struct sockaddr *addr;
    const char *connect_addrstr = "127.0.0.1:8046";
//    const char *connect_addrstr = "unix://test-unix-socket";
    addr = sockaddr_from_str(connect_addrstr, &connect_addrlen);
    if (addr == NULL) {
        printf("Error converting \"%s\" to sockaddr.\n", connect_addrstr);
        exit(EXIT_FAILURE);
    }
    memcpy(connect_addr, addr, connect_addrlen);

    printf("Spawning %d threads...\n", nthreads);
    printf("Connecting to %s\n",
           sockaddr_to_str(connect_addr, connect_addrlen));

    EXIT_ON_NEG(pipe(sigint_pipe));
    EXIT_ON_NEG(pipe(start_pipe));

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    EXIT_ON_NEG(sigaction(SIGINT, &sa, NULL));

    EXIT_ON_NULL(threads = calloc(nthreads, sizeof(pthread_t)));
    EXIT_ON_NULL(thread_times = calloc(nthreads, sizeof(uint64_t)));
    for (i = 0; i < nthreads; i++) {
        EXIT_ON_PTERR(pthread_create(&threads[i], NULL, thread_start,
                                     (void *)((intptr_t)i)));
    }
    /* wait for threads to start up. */
    while (nthreads_ready < nthreads) {
        usleep(1000);
    }
    LOGF(0, "All threads ready, starting test.\n");
    start = now_us();
    EXIT_ON_NEG(write(start_pipe[1], &byte, 1));
    /* wait for threads to finish. */
    for (i = 0; i < nthreads; i++) {
        void *retval = NULL;
        EXIT_ON_PTERR(pthread_join(threads[i], &retval));
        if (retval != PTHREAD_CANCELED && retval != NULL) {
            thread_times[i] = *((uint64_t *)retval);
            free(retval);
        }
    }
    end = now_us();
    uint64_t total = 0;
    for (i = 0; i < nthreads; i++) {
        total += thread_times[i];
        LOGF(9, "Thread %d took %" PRIu64 " microseconds.\n", i,
             thread_times[i]);
    }
    printf("avg time: %" PRIu64 " microseconds.\n", total / nthreads);
    printf("main took %" PRIu64 " microseconds.\n", end - start);
    printf("%d %d %d -- %" PRIu64 "\n", nthreads, nconnections, nexecs,
           total / nthreads);
    return 0;
}
