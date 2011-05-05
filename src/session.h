/*
 * session.h
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#ifndef SESSION_H_
#define SESSION_H_

#include "msg.h"
#include "queue.h"
#include "worker.h"

struct client;
struct rbuf;

enum session_wevent_type {
    SESSION_WEVENT_OUTPUT,
    SESSION_WEVENT_PIPE_ERR,
    SESSION_WEVENT_EXITED,
};

struct session_wevent {
    STAILQ_ENTRY(session_wevent) q_entry;
    enum session_wevent_type type;
    union {
        struct {
            int nrbufs;
            uint16_t nbytes;
            enum msg_type mtype;
            struct rbuf *rbufs[0];
            /* rbuf pointer array in extra malloc-ed space. */
        } output;
        enum msg_type mtype;
        int rstatus;
    };
};

enum session_timeout_state {
    SESSION_TIMEOUT_STATE_NONE,
    SESSION_TIMEOUT_STATE_NO_CLIENTS,
};

struct session {
    struct worker *worker;
    LIST_HEAD(, client) clients;
    LIST_ENTRY(session) bucket_entry;
    STAILQ_HEAD(, session_wevent) queued_wevents;
    TAILQ_ENTRY(session) timeout_entry;
    uint32_t timeout_tick;
    uint32_t id;
    enum session_timeout_state timeout_state : 8;
};

struct session *session_start(struct client *client);
struct session *session_lookup(uint32_t session_id);
void session_add_client(struct session *session, struct client *client);
void session_remove_client(EV_P_ struct session *session,
                           struct client *client);

int session_start_worker(EV_P_ struct session *session);
/**
 * Calls client_on_worker_*_cb for all clients connected to the session,
 * and empties the session's pending output.
 * @return -1 on error, 0 otherwise.
 */
int session_get_queued_wevents(EV_P_ struct session *session,
                               struct client *client);

static inline uint32_t
session_id(struct session *session)
{
    return session->id;
}

static inline bool
session_worker_started(struct session *session)
{
    return session->worker != NULL && worker_alive(session->worker);
}

static inline bool
session_worker_alive(struct session *session)
{
    return session->worker != NULL && worker_alive(session->worker);
}

static inline int
session_worker_signal(struct session *session, int sig)
{
    if (session->worker == NULL) {
        return -1;
    }
    return worker_signal(session->worker, sig);
}

static inline int
session_worker_write_input(EV_P_ struct session *session,
                           const struct msg_hdr *hdr,
                           struct rbuf *body)
{
    if (session->worker == NULL) {
        return -1;
    }
    return worker_write_input(EV_A_ session->worker, hdr, body);
}


static inline uint32_t
session_worker_pid(struct session *session)
{
    if (session->worker == NULL) {
        return 0;
    }
    return worker_pid(session->worker);
}

void session_on_worker_output_cb(EV_P_ struct session *session,
                                 struct rbuf **rbufs, int nrbufs,
                                 uint16_t nbytes, enum msg_type type);
void session_on_worker_pipe_err_cb(EV_P_ struct session *session,
                                   enum msg_type type);
void session_on_worker_exited_cb(EV_P_ struct session *session, int rstatus);

#endif /* SESSION_H_ */
