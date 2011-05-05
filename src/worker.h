/*
 * worker.h
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#ifndef WORKER_H_
#define WORKER_H_

#include <ev.h>

#include "writeq.h"

struct msg_hdr;
struct rbuf;
struct session;

struct worker {
    struct session *session;
    ev_child child_watcher;
    ev_io stdin_w;
    ev_io stdout_w;
    ev_io stderr_w;
    ev_io msgin_w;
    ev_io msgout_w;
    struct writeq stdin_writeq;
    struct writeq msgin_writeq;
    bool f_alive : 1;
    bool f_stdin_eof : 1;
    bool f_msgin_eof : 1;
};

static inline int
worker_pid(struct worker *w)
{
    return w->child_watcher.pid;
}

struct worker *worker_start(EV_P_ struct session *session);
void worker_stop(EV_P_ struct worker *worker);

static inline bool
worker_alive(struct worker *w)
{
    return w->f_alive;
}

static inline int
worker_signal(struct worker *worker, int sig)
{
    LOGF(3, "=== %d: worker sending signal %d\n", worker_pid(worker), sig);
    if (kill(worker_pid(worker), sig) < 0) {
        LOG_ERRNO("kill()");
        return -1;
    }
    return 0;
}

int worker_write_input(EV_P_ struct worker *worker, const struct msg_hdr *hdr,
                       struct rbuf *body);

#endif /* WORKER_H_ */
