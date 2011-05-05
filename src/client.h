/*
 * client.h
 *
 *  Created on: Mar 20, 2011
 *      Author: alex
 */

#ifndef CLIENT_H_
#define CLIENT_H_

#include <arpa/inet.h>
#include <ev.h>

#include "def.h"
#include "auth.h"
#include "msg.h"
#include "writeq.h"

struct session;

enum client_timeout_state {
    CLIENT_TIMEOUT_STATE_NONE,
    CLIENT_TIMEOUT_STATE_UNAUTHED,
    CLIENT_TIMEOUT_STATE_AUTH_FAIL,
};

struct client {
    ev_io watcher;
    struct msg_rx msg_rx;
    struct writeq writeq;
    struct session *session;
    const struct auth_entry *auth_entry;
    LIST_ENTRY(client) clients_entry;
    LIST_ENTRY(client) session_clients_entry;
    TAILQ_ENTRY(client) timeout_entry;
    uint32_t timeout_tick;
    enum client_timeout_state timeout_state : 8;
    uint8_t nonce[AUTH_NONCE_LEN];
};

static inline int
client_fd(const struct client *client)
{
    return client->watcher.fd;
}

/**
 * Called by server after an accept().  fd is an open, non-blocking socket.
 */
void client_accept(EV_P_ int fd, const struct sockaddr *addr,
                   socklen_t addrlen);

void client_stop(EV_P_ struct client *client);

int client_on_worker_output_cb(EV_P_ struct client *client,
                               struct rbuf **rbufs, int nrbufs,
                               uint16_t nbytes, enum msg_type type);
int client_on_worker_pipe_err_cb(EV_P_ struct client *client,
                                 enum msg_type type);
int client_on_worker_exited_cb(EV_P_ struct client *client, int rstatus);

#endif /* CLIENT_H_ */
