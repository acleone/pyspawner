/*
 * session.c
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#include <stdlib.h>
#include <alloca.h>

#include "config.h"
#include "client.h"
#include "session.h"
#include "tick.h"

#define SESSION_TABLE_HASHSIZE   EV_PID_HASHSIZE

struct session_bucket {
    LIST_HEAD(, session) list;
};

static struct session_bucket session_table[SESSION_TABLE_HASHSIZE];
static uint32_t session_next_id;
static int nsessions;
static TAILQ_HEAD(, session) noclients_list;




static inline struct session_bucket *
session_bucket(uint32_t id)
{
    return &session_table[id % SESSION_TABLE_HASHSIZE];
}

static inline void
session_switch_timeout(struct session *session,
                       enum session_timeout_state newstate)
{
    LOGF(6, "--- %d: session_timeout %d -> %d\n", session_id(session),
         session->timeout_state, newstate);
    if (session->timeout_state == SESSION_TIMEOUT_STATE_NO_CLIENTS) {
        TAILQ_REMOVE(&noclients_list, session, timeout_entry);
    }
    if (newstate == SESSION_TIMEOUT_STATE_NO_CLIENTS) {
        TAILQ_INSERT_TAIL(&noclients_list, session, timeout_entry);
        session->timeout_tick = ticks + config.session_noclients_timeout_ticks;
    }
    session->timeout_state = newstate;
}

struct session *
session_start(struct client *client)
{
    struct session *session;

    if ((session = calloc(1, sizeof(*session))) == NULL) {
        return NULL;
    }
    session->id = session_next_id++;
    nsessions++;
    LIST_INIT(&session->clients);
    STAILQ_INIT(&session->queued_wevents);
    LIST_INSERT_HEAD(&session_bucket(session->id)->list, session, bucket_entry);
    session_add_client(session, client);

    LOGF(3, "--- %d: session started\n", session_id(session));
    return session;
}

static void
session_free_wevents(struct session *session)
{
    int i;
    struct session_wevent *wevent, *tmp;
    STAILQ_FOREACH_SAFE(wevent, &session->queued_wevents, q_entry, tmp) {
        if (wevent->type == SESSION_WEVENT_OUTPUT) {
            for (i = 0; i < wevent->output.nrbufs; i++) {
                wevent->output.rbufs[i] = rbuf_release(wevent->output.rbufs[i]);
            }
        }
        free(wevent);
    }
}

static void
session_stop(EV_P_ struct session *session)
{
    struct client *client, *next_client;

    LOGF(3, "--- %d: session ended\n", session_id(session));

    if (session->worker != NULL) {
        worker_stop(EV_A_ session->worker);
    }
    session->worker = NULL;

    if (!LIST_EMPTY(&session->clients)) {
        LOGF(0, "--- %d: WARNING: ending session that still has clients\n",
             session_id(session));
        LIST_FOREACH_SAFE(client, &session->clients, session_clients_entry,
                          next_client) {
            client->session = NULL;
        }
    }
    session_switch_timeout(session, SESSION_TIMEOUT_STATE_NONE);
    nsessions--;
    LIST_REMOVE(session, bucket_entry);
    session_free_wevents(session);
    free(session);
}

struct session *
session_lookup(uint32_t session_id)
{
    struct session *session;
    struct session_bucket *bucket;

    bucket = session_bucket(session_id);
    LIST_FOREACH(session, &bucket->list, bucket_entry) {
        if (session->id == session_id) {
            return session;
        }
    }
    return NULL;
}

void
session_add_client(struct session *session, struct client *client)
{
    if (session->timeout_state != SESSION_TIMEOUT_STATE_NONE) {
        session_switch_timeout(session, SESSION_TIMEOUT_STATE_NONE);
    }
    LIST_INSERT_HEAD(&session->clients, client, session_clients_entry);
    LOGF(5, "--- %d: added client %d\n", session_id(session),
         client_fd(client));
}

void
session_remove_client(EV_P_ struct session *session, struct client *client)
{
    LIST_REMOVE(client, session_clients_entry);
    LOGF(5, "--- %d: removed client %d\n", session_id(session),
         client_fd(client));
    if (LIST_EMPTY(&session->clients)) {
        if (session_worker_alive(session)) {
            // worker is alive, end the session after a timeout.
            session_switch_timeout(session, SESSION_TIMEOUT_STATE_NO_CLIENTS);
        } else {
            // no clients and no worker - end the session immediately.
            LOGF(6, "--- %d: empty session with no worker - stopping\n",
                 session_id(session));
            session_stop(EV_A_ session);
        }
    }
}

int
session_start_worker(EV_P_ struct session *session)
{
    if (session_worker_started(session)) {
        return -1;
    }
    if (session->worker != NULL) {
        LOGF(5, "--- %d: session had old worker pid %d, stopping\n",
             session_id(session), worker_pid(session->worker));
        worker_stop(EV_A_ session->worker);
        session->worker = NULL;
    }
    if ((session->worker = worker_start(EV_A_ session)) == NULL) {
        return -1;
    }
    LOGF(3, "--- %d: session started worker pid %d\n", session_id(session),
         worker_pid(session->worker));
    return 0;
}

int
session_get_queued_wevents(EV_P_ struct session *session, struct client *client)
{
    struct session_wevent *wevent;
    int rc = -1;

    STAILQ_FOREACH(wevent, &session->queued_wevents, q_entry) {
        switch (wevent->type) {
        case SESSION_WEVENT_OUTPUT:
            if (client_on_worker_output_cb(EV_A_ client, wevent->output.rbufs,
                                           wevent->output.nrbufs,
                                           wevent->output.nbytes,
                                           wevent->output.mtype) < 0) {
                goto out;
            }
            break;
        case SESSION_WEVENT_PIPE_ERR:
            if (client_on_worker_pipe_err_cb(EV_A_ client, wevent->mtype) < 0) {
                goto out;
            }
            break;
        case SESSION_WEVENT_EXITED:
            if (client_on_worker_exited_cb(EV_A_ client, wevent->rstatus) < 0) {
                goto out;
            }
            break;
        }
    }
    rc = 0;

 out:
    session_free_wevents(session);
    STAILQ_INIT(&session->queued_wevents);
    return rc;
}

void
session_on_worker_output_cb(EV_P_ struct session *session, struct rbuf **rbufs,
                            int nrbufs, uint16_t nbytes, enum msg_type type)
{
    struct session_wevent *wevent;
    struct client *client, *next_client;
    int i;

    if (LIST_EMPTY(&session->clients)) {
        /* save output for when a client joins. */
        if ((wevent = malloc(sizeof(*wevent) +
                             sizeof(struct rbuf *) * nrbufs)) == NULL) {
            return;
        }
        wevent->type = SESSION_WEVENT_OUTPUT;
        wevent->output.nrbufs = nrbufs;
        wevent->output.nbytes = nbytes;
        wevent->output.mtype = type;
        for (i = 0; i < nrbufs; i++) {
            wevent->output.rbufs[i] = rbuf_add_ref(rbufs[i]);
        }
        STAILQ_INSERT_TAIL(&session->queued_wevents, wevent, q_entry);
    } else {
        /* send output directly to clients. */
        LIST_FOREACH_SAFE(client, &session->clients, session_clients_entry,
                          next_client) {
            if (client_on_worker_output_cb(EV_A_ client, rbufs, nrbufs, nbytes,
                                           type) < 0) {
                client_stop(client);
            }
        }
    }
}

void
session_on_worker_pipe_err_cb(EV_P_ struct session *session,
                                enum msg_type type)
{
    struct session_wevent *wevent;
    struct client *client, *next_client;

    if (LIST_EMPTY(&session->clients)) {
        /* save output for when a client joins. */
        if ((wevent = malloc(sizeof(*wevent))) == NULL) {
            return;
        }
        wevent->type = SESSION_WEVENT_PIPE_ERR;
        wevent->mtype = type;
        STAILQ_INSERT_TAIL(&session->queued_wevents, wevent, q_entry);
    } else {
        /* send output directly to clients. */
        LIST_FOREACH_SAFE(client, &session->clients, session_clients_entry,
                          next_client) {
            if (client_on_worker_pipe_err_cb(EV_A_ client, type) < 0) {
                client_stop(client);
            }
        }
    }
}

void
session_on_worker_exited_cb(EV_P_ struct session *session, int rstatus)
{
    struct session_wevent *wevent;
    struct client *client, *next_client;

    if (LIST_EMPTY(&session->clients)) {
        /* save output for when a client joins. */
        if ((wevent = malloc(sizeof(*wevent))) == NULL) {
            return;
        }
        wevent->type = SESSION_WEVENT_EXITED;
        wevent->rstatus = rstatus;
        STAILQ_INSERT_TAIL(&session->queued_wevents, wevent, q_entry);
    } else {
        /* send output directly to clients. */
        LIST_FOREACH_SAFE(client, &session->clients, session_clients_entry,
                          next_client) {
            if (client_on_worker_exited_cb(EV_A_ client, rstatus) < 0) {
                client_stop(client);
            }
        }
    }
}




void
session_sysinit(EV_P)
{
    int i;
    TAILQ_INIT(&noclients_list);

    for (i = 0; i < SESSION_TABLE_HASHSIZE; i++) {
        LIST_INIT(&session_table[i].list);
    }
}

void
session_sysuninit(EV_P)
{
    struct session *session, *tmp;
    int i;
    if (nsessions == 0) {
        return;
    }
    DEBUGF(0, "stopping %d sessions\n", nsessions);
    for (i = 0; i < SESSION_TABLE_HASHSIZE; i++) {
        LIST_FOREACH_SAFE(session, &session_table[i].list, bucket_entry, tmp) {
            session_stop(EV_A_ session);
        }
    }
}

void
session_timer_tick(EV_P)
{
    struct session *session, *tmp;
    // remove empty sessions that have timed out.
    TAILQ_FOREACH_SAFE(session, &noclients_list, timeout_entry, tmp) {
        if (session->timeout_tick != ticks) {
            break;
        }
        LOGF(3, "--- %d: session timed out\n", session_id(session));
        session_stop(EV_A_ session);
    }
}
SET_ENTRY(TIMER_TICK, session_timer_tick);
