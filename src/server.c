/*
 * tcpserve.c
 *
 *  Created on: Feb 19, 2011
 *      Author: alex
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ev.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "def.h"
#include "lib.h"
#include "maxfd.h"
#include "client.h"
#include "config.h"

static ev_io listen_watcher;

/**
 * Kept open to /dev/null, used when we run out of fd's.
 */
static int discard_fd = -1;
static const char *discard_path = "/dev/null";
static const int discard_flags = O_NONBLOCK | O_CLOEXEC | O_RDONLY;

static void
listen_cb(EV_P_ ev_io *w, int revents)
{
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    bool discard = false;

    if (revents & EV_ERROR) {
        printf("%d error: listen_cb had EV_ERROR\n", listen_watcher.fd);
        ev_break(EV_A_ EVBREAK_ALL);
    }

 retry:
    for (;;) {
        addrlen = sizeof(addr);
        fd = accept4(listen_watcher.fd, (struct sockaddr *)&addr, &addrlen,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            switch (errno) {
            case EAGAIN:
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            case ENOBUFS:
            case ENOMEM:
                goto out;

            case EMFILE:
            case ENFILE:
                if (discard_fd < 0) {
                    /* we already closed the discard_fd, nothing we can do. */
                    goto out;
                }
                close(discard_fd);
                discard_fd = -1;
                discard = true;
                goto retry;

            case ECONNABORTED:
            case EINTR:
            case EPERM:
            case ENETDOWN:
            case EPROTO:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
                LOG_ERRNO("accept4()");
                goto retry;

            default:
                EXIT_ON_NEG_FMT(fd, "accept4()");
            }
        }
        maxfd_update(fd);
        if (discard) {
            close(fd);
            goto retry;
        }
        client_accept(EV_A_ fd, (struct sockaddr *)&addr, addrlen);
    }
 out:
    if (discard_fd < 0) {
        discard_fd = open(discard_path, discard_flags);
        maxfd_update(discard_fd);
        /* ignore error. */
    }
}

void
server_sysinit(EV_P)
{
    int listen_fd;

    EXIT_ON_NEG(discard_fd = open(discard_path, discard_flags));
    maxfd_update(discard_fd);

    listen_fd = create_listening_sock(&config.listen_addr,
                                      config.listen_addrlen,
                                      config.listen_backlog);
    maxfd_update(listen_fd);
    ev_io_init(&listen_watcher, listen_cb, listen_fd, EV_READ);
    ev_io_start(EV_A_ &listen_watcher);

    LOGF(3, "%d @ %s\n", listen_fd, sockaddr_to_str(&config.listen_addr,
                                                    config.listen_addrlen));
}

void
server_sysuninit(EV_P)
{
    ev_io_stop(EV_A_ &listen_watcher);
    close(listen_watcher.fd);
    close(discard_fd);
}
