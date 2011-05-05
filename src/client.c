/*
 * client.c
 *
 *  Created on: Mar 20, 2011
 *      Author: alex
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "def.h"
#include "lib.h"
#include "auth.h"
#include "client.h"
#include "config.h"
#include "maxfd.h"
#include "msg.h"
#include "pyenv.h"
#include "queue.h"
#include "session.h"
#include "tick.h"

static inline void client_start(EV_P_ struct client *client, int fd,
                                const struct sockaddr *addr,
                                socklen_t addrlen);

static void client_cb(EV_P_ ev_io *w, int revents);

static int client_got_msg(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body);

static LIST_HEAD(, client) clients;
static int nclients;
static TAILQ_HEAD(, client) unauthed_list;
static int nunauthed_clients;
static TAILQ_HEAD(, client) auth_fail_list;
static int nauth_fail;

/**
 * Arms writes if they aren't armed already.
 */
static inline void
client_arm_writes(EV_P_ struct client *client)
{
    ev_io * const w = &client->watcher;
    if (!(w->events & EV_WRITE)) {
        int new_events = (w->events | EV_WRITE) & (EV_READ | EV_WRITE);
        LOGF(9, "  %d arming writes\n", client_fd(client));
        ev_io_stop(EV_A_ w);
        ev_io_set(w, client_fd(client), new_events);
        ev_io_start(EV_A_ w);
    }
}

/**
 * Disarms reads if they are armed.
 * @return true if the client has been stopped.
 */
static inline bool
client_disarm_reads(EV_P_ struct client *client)
{
    ev_io * const w = &client->watcher;
    LOGIF(9) {
        if ((w->events & EV_READ)) {
            printf("  %d disarming reads\n", client_fd(client));
        }
    }
    if ((w->events & EV_WRITE)) {
        if ((w->events & EV_READ)) {
            ev_io_stop(EV_A_ w);
            ev_io_set(w, client_fd(client), EV_WRITE);
            ev_io_start(EV_A_ w);
        }
        return false;
    }
    ev_io_stop(EV_A_ w);
    w->events = 0;
    return true;
}

/**
 * Disarms writes if they are armed.
 * @return true if the client has been stopped.
 */
static inline bool
client_disarm_writes(EV_P_ struct client *client)
{
    ev_io * const w = &client->watcher;
    LOGIF(9) {
        if ((w->events & EV_WRITE)) {
            printf("  %d disarming writes\n", client_fd(client));
        }
    }
    if ((w->events & EV_READ)) {
        if ((w->events & EV_WRITE)) {
            ev_io_stop(EV_A_ w);
            ev_io_set(w, client_fd(client), EV_READ);
            ev_io_start(EV_A_ w);
        }
        return false;
    }
    ev_io_stop(EV_A_ w);
    w->events = 0;
    return true;
}

/**
 * Remove the client from the previous timeout and add to the new timeout.
 */
static inline void
client_switch_timeout(struct client *client, enum client_timeout_state newstate)
{
    LOGF(6, "  %d client_timeout %d -> %d\n", client_fd(client),
         client->timeout_state, newstate);
    if (client->timeout_state == CLIENT_TIMEOUT_STATE_UNAUTHED) {
        TAILQ_REMOVE(&unauthed_list, client, timeout_entry);
        nunauthed_clients--;
    } else if (client->timeout_state == CLIENT_TIMEOUT_STATE_AUTH_FAIL) {
        TAILQ_REMOVE(&auth_fail_list, client, timeout_entry);
        nauth_fail--;
    }
    if (newstate == CLIENT_TIMEOUT_STATE_UNAUTHED) {
        TAILQ_INSERT_TAIL(&unauthed_list, client, timeout_entry);
        nunauthed_clients++;
        client->timeout_tick = ticks + config.client_unauth_timeout_ticks;
    } else if (newstate == CLIENT_TIMEOUT_STATE_AUTH_FAIL) {
        TAILQ_INSERT_TAIL(&auth_fail_list, client, timeout_entry);
        nauth_fail++;
        client->timeout_tick = ticks + config.client_auth_fail_timeout_ticks;
    }
    client->timeout_state = newstate;
}

/**
 * The following functions mirror the writeq_append_* functions, but they
 * also prepend a message header.
 * @param sid -1 if we should use the last decoded sid (for replies).
 */
static inline int
client_writeq_hdr(struct client *client, uint8_t sid, uint16_t len,
                  enum msg_type type)
{
    struct msg_hdr hdr = {
        .type = type,
        .sid = sid,
        .flags = { .byte = 0 },
        .len = len,
    };
    uint8_t hdr_buf[MSG_HDR_LEN];
    LOGIF(9) {
        printf("< %d ", client_fd(client));
        print_msg_hdr(stdout, &hdr);
        printf("\n");
    }
    msg_hdr_to_buf(&hdr, hdr_buf);
    return writeq_append_copy(&client->writeq, hdr_buf, MSG_HDR_LEN);
}

static inline int
client_writeq_msg_rbuf(struct client *client, struct rbuf *rbuf,
                              int sid, enum msg_type type)
{
    if (client_writeq_hdr(client, sid, rbuf->len, type) < 0) {
        return -1;
    }
    return writeq_append_rbuf(&client->writeq, rbuf);
}

static inline int
client_writeq_msg_copy(struct client *client, const void *buf,
                              uint16_t len, int sid, enum msg_type type)
{
    if (client_writeq_hdr(client, sid, len, type) < 0) {
        return -1;
    }
    return writeq_append_copy(&client->writeq, buf, len);
}

static inline int
client_writeq_msg_ptr(struct client *client, const void *ptr,
                             uint16_t len, int sid, enum msg_type type)
{
    if (client_writeq_hdr(client, sid, len, type) < 0) {
        return -1;
    }
    return writeq_append_ptr(&client->writeq, ptr, len);
}

static inline int
client_writeq_empty_success(struct client *client, uint8_t sid)
{
    return client_writeq_hdr(client, sid, 0, MSG_TYPE_SUCCESS);
}

static inline int
client_writeq_error(struct client *client, const char *errstr)
{
    const int len = strlen(errstr);
    if (client_writeq_hdr(client, msg_rx_last_hdr(&client->msg_rx)->sid,
                          len, MSG_TYPE_ERROR) < 0) {
        return -1;
    }
    return writeq_append_ptr(&client->writeq, errstr, len);
}

/**
 * Tries to send out data in writeq, and arm writes if not all was sent.
 * Assumes that writes are currently disarmed.
 * @return -1 on error.
 */
static inline int
client_try_write_unarmed(EV_P_ struct client *client)
{
    if (writeq_write(&client->writeq, client_fd(client)) < 0) {
        return -1;
    }
    if (!writeq_is_empty(&client->writeq)) {
        client_arm_writes(EV_A_ client);
    }
    return 0;
}


void
client_accept(EV_P_ int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct client *client;

    if ((client = malloc(sizeof(*client))) == NULL) {
        close(fd);
        return;
    }
    client_start(EV_A_ client, fd, addr, addrlen);
}

static inline void
client_start(EV_P_ struct client *client, int fd, const struct sockaddr *addr,
             socklen_t addrlen)
{
    LOGF(3, "{ %d %s\n", fd, sockaddr_to_str(addr, addrlen));
    memset(client, 0, sizeof(*client));
    ev_io_init(&client->watcher, client_cb, fd, EV_READ);
    ev_io_start(EV_A_ &client->watcher);
    msg_rx_init(&client->msg_rx);
    writeq_init(&client->writeq);

    LIST_INSERT_HEAD(&clients, client, clients_entry);
    nclients++;

    client_switch_timeout(client, CLIENT_TIMEOUT_STATE_UNAUTHED);

    if (auth_get_nonce(client->nonce) < 0) {
        goto drop;
    }
    if (client_writeq_msg_ptr(client, client->nonce, AUTH_NONCE_LEN, 0,
                              MSG_TYPE_AUTH_NONCE) < 0) {
        goto drop;
    }
    if (client_try_write_unarmed(EV_A_ client) < 0) {
        goto drop;
    }

    LOGF(5, "  %d waiting for MSG_TYPE_AUTH_PW_REPLY\n", client_fd(client));

    return;

 drop:
    client_stop(client);
}

void
client_stop(EV_P_ struct client *client)
{
    int fd = client_fd(client);
    LOGF(3, "} %d\n", fd);

    if (client->session != NULL) {
        session_remove_client(EV_A_ client->session, client);
    }
    client->session = NULL;

    if (ev_is_active(&client->watcher)) {
        ev_io_stop(EV_A_ &client->watcher);
    }

    writeq_uninit(&client->writeq);
    msg_rx_uninit(&client->msg_rx);

    LIST_REMOVE(client, clients_entry);
    nclients--;

    client_switch_timeout(client, CLIENT_TIMEOUT_STATE_NONE);
    close(fd);
    free(client);
}

static void
client_cb(EV_P_ ev_io *w, int revents)
{
    struct client *client = CONTAINER_OF(w, struct client, watcher);
    int rc = 0;

    if ((revents & EV_ERROR)) {
        goto drop;
    }

    if ((revents & EV_READ)) {
        switch (msg_rx_read1(&client->msg_rx, client_fd(client))) {
        case MSG_RX_RC_ERROR:
        case MSG_RX_RC_BAD_HDR_CHKSUM:
            goto drop;
        case MSG_RX_RC_EOF:
            if (client_disarm_reads(EV_A_ client)) {
                goto drop;
            }
            goto tx;
        case MSG_RX_RC_NEED_MORE:
            goto tx;
        case MSG_RX_RC_GOT_MSG:
            break;
        }
        rc = client_got_msg(EV_A_ client, msg_rx_last_hdr(&client->msg_rx),
                            msg_rx_last_body(&client->msg_rx));
        msg_rx_release_last_body(&client->msg_rx);
    }
 tx:
    if (!writeq_is_empty(&client->writeq)) {
        if (writeq_write(&client->writeq, client_fd(client)) < 0) {
            goto drop;
        }
        if (writeq_is_empty(&client->writeq)) {
            if (client_disarm_writes(EV_A_ client)) {
                goto drop;
            }
        } else {
            client_arm_writes(EV_A_ client);
        }
    }
    if (rc != 0) {
        goto drop;
    }
    return;

 drop:
    client_stop(client);
}

static int
on_MSG_TYPE_AUTH_PW_REPLY(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body)
{
    if ((client->auth_entry = auth_client(client->nonce, body)) == NULL) {
        // authentication failure - wait a bit before dropping client
        client_switch_timeout(client, CLIENT_TIMEOUT_STATE_AUTH_FAIL);
        client_disarm_reads(EV_A_ client);
        return 0;
    }
    LOGF(4, "  %d successfully authenticated as %.*s\n", client_fd(client),
         client->auth_entry->uname_len, client->auth_entry->uname);
    client_switch_timeout(client, CLIENT_TIMEOUT_STATE_NONE);
    return client_writeq_empty_success(client, hdr->sid);
}

static int
on_MSG_TYPE_START_SESSION(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body)
{
    uint32_t sessid_le;
    if (client->session != NULL) {
        return client_writeq_error(client, "already in session");
    }
    if ((client->session = session_start(client)) == NULL) {
        return -1;
    }
    sessid_le = htole32(session_id(client->session));
    return client_writeq_msg_copy(client, &sessid_le, 4, hdr->sid,
                                  MSG_TYPE_SUCCESS);
}

static int
on_MSG_TYPE_JOIN_SESSION(EV_P_ struct client *client,
                         const struct msg_hdr *hdr, struct rbuf *body)
{
    uint32_t sessid;
    if (client->session != NULL) {
        return client_writeq_error(client, "already in session");
    }
    if (hdr->len != 4) {
        return client_writeq_error(client, "bad msglen");
    }
    sessid = letoh32(*((uint32_t *)body->data));
    if ((client->session = session_lookup(sessid)) == NULL) {
        return client_writeq_error(client, "bad sessid");
    }
    session_add_client(client->session, client);
    if (client_writeq_empty_success(client, hdr->sid) < 0) {
        return -1;
    }
    return session_get_queued_wevents(EV_A_ client->session, client);
}

static int
on_MSG_TYPE_LEAVE_SESSION(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body)
{
    if (client->session != NULL) {
        session_remove_client(EV_A_ client->session, client);
        client->session = NULL;
    }
    return client_writeq_empty_success(client, hdr->sid);
}

static int
on_MSG_TYPE_START_WORKER(EV_P_ struct client *client,
                         const struct msg_hdr *hdr, struct rbuf *body)
{
    uint32_t pid_le;
    if (client->session == NULL) {
        return client_writeq_error(client, "not in session");
    }
    if (session_worker_started(client->session)) {
        return client_writeq_error(client, "worker already started");
    }
    if (session_start_worker(EV_A_ client->session) < 0) {
        return client_writeq_error(client, "error starting worker");
    }
    pid_le = htole32(session_worker_pid(client->session));
    return client_writeq_msg_copy(client, &pid_le, 4, hdr->sid,
                                  MSG_TYPE_SUCCESS);
}

static int
on_MSG_TYPE_SIGNAL_WORKER(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body)
{
    uint32_t sig;
    if (client->session == NULL) {
        return client_writeq_error(client, "not in session");
    }
    if (!session_worker_alive(client->session)) {
        return client_writeq_error(client, "worker not alive");
    }
    if (hdr->len != 4) {
        return client_writeq_error(client, "bad msglen");
    }
    sig = letoh32(*((uint32_t *)body->data));
    if (session_worker_signal(client->session, sig) < 0) {
        return client_writeq_error(client, "error signaling worker");
    }
    return client_writeq_empty_success(client, hdr->sid);
}

static int
on_MSG_TYPE_WORKER_PIPEIN(EV_P_ struct client *client,
                          const struct msg_hdr *hdr, struct rbuf *body)
{
    if (client->session == NULL) {
        return client_writeq_error(client, "not in session");
    }
    if (!session_worker_alive(client->session)) {
        return client_writeq_error(client, "worker not alive");
    }
    if (session_worker_write_input(EV_A_ client->session, hdr, body) < 0) {
        return client_writeq_error(client, "error writing input");
    }
    return client_writeq_empty_success(client, hdr->sid);
}

typedef int (*msg_recv_cb)(EV_P_ struct client *client,
                           const struct msg_hdr *hdr, struct rbuf *body);

#define _CB(t)  [t] = on_##t
static msg_recv_cb
ON_MSG_RECV_CBS[MSG_TYPE_LAST] = {
    _CB(MSG_TYPE_AUTH_PW_REPLY),
    _CB(MSG_TYPE_START_SESSION),
    _CB(MSG_TYPE_JOIN_SESSION),
    _CB(MSG_TYPE_LEAVE_SESSION),
    _CB(MSG_TYPE_START_WORKER),
    _CB(MSG_TYPE_SIGNAL_WORKER),
    [MSG_TYPE_WORKER_STDIN] = on_MSG_TYPE_WORKER_PIPEIN,
    [MSG_TYPE_WORKER_MSGIN] = on_MSG_TYPE_WORKER_PIPEIN,
};
#undef _CB

/**
 * Returns -1 if the client should be dropped.
 */
static int
client_got_msg(EV_P_ struct client *client, const struct msg_hdr *hdr,
               struct rbuf *body)
{
    msg_recv_cb cb;
    LOGIF(9) {
        printf("> %d ", client_fd(client));
        print_msg_hdr(stdout, hdr);
        printf("\n");
        LOGIF(12) {
            printf("    ");
            print_repr(stdout, body->data, body->len, true);
            printf("\n");
        }
    }
    if (hdr->type >= MSG_TYPE_LAST) {
        return -1;
    }
    cb = ON_MSG_RECV_CBS[hdr->type];
    if (cb == NULL) {
        DEBUGF(0, "  %d Warning - unhandled msg type=%d\n", client_fd(client),
               hdr->type);
        return -1;
    }
    return cb(EV_A_ client, hdr, body);
}

int
client_on_worker_output_cb(EV_P_ struct client *client,
                           struct rbuf **rbufs, int nrbufs,
                           uint16_t nbytes, enum msg_type type)
{
    int i;
    if (client_writeq_hdr(client, 0, nbytes, type) < 0) {
        return -1;
    }
    for (i = 0; i < nrbufs; i++) {
        if (writeq_append_rbuf(&client->writeq, rbufs[i]) < 0) {
            return -1;
        }
    }
    return client_try_write_unarmed(EV_A_ client);
}

int
client_on_worker_pipe_err_cb(EV_P_ struct client *client, enum msg_type type)
{
    int32_t pipe_le = htole32(type);
    if (client_writeq_msg_copy(client, &pipe_le, 4, 0,
                               MSG_TYPE_PIPE_ERROR) < 0) {
        return -1;
    }
    return client_try_write_unarmed(EV_A_ client);
}

int
client_on_worker_exited_cb(EV_P_ struct client *client, int rstatus)
{
    int32_t status_le = htole32(rstatus);
    if (client_writeq_msg_copy(client, &status_le, 4, 0,
                               MSG_TYPE_WORKER_EXITED) < 0) {
        return -1;
    }
    return client_try_write_unarmed(EV_A_ client);
}


void
client_sysinit(EV_P)
{
    LIST_INIT(&clients);
    TAILQ_INIT(&unauthed_list);
    TAILQ_INIT(&auth_fail_list);
}

void
client_sysuninit(EV_P)
{

}

static void
client_timer_tick(EV_P)
{
    struct client *client, *tmp;
    // remove unauthenticated clients who have timed out.
    TAILQ_FOREACH_SAFE(client, &unauthed_list, timeout_entry, tmp) {
        if (client->timeout_tick != ticks) {
            break;
        }
        LOGF(2, "  %d unauth timeout\n", client_fd(client));
        client_stop(EV_A_ client);
    }
    // reply to authentication failures after a timeout.
    TAILQ_FOREACH_SAFE(client, &auth_fail_list, timeout_entry, tmp) {
        if (client->timeout_tick != ticks) {
            break;
        }
        client_writeq_error(client, "auth fail");
        writeq_write(&client->writeq, client_fd(client));
        client_stop(EV_A_ client);
    }
}
SET_ENTRY(TIMER_TICK, client_timer_tick);
