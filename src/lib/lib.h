/*
 * lib.h
 *
 *  Created on: Feb 21, 2011
 *      Author: alex
 */

#ifndef LIB_H_
#define LIB_H_

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "def.h"

/**
 * Print 'hello wor\xe7', ala python.
 */
void print_repr(FILE *f, const void *str, int len, bool with_quotes);

void print_iov_repr(FILE *f, const struct iovec *iov, int iovcnt);

void names_to_uid_gid(const char *usrname, const char *grpname, uid_t *uid_out,
                      gid_t *gid_out);
void drop_to_uid_gid(uid_t uid, gid_t gid);

void raise_rlimit(int new_limit);

int create_listening_sock(const struct sockaddr *addr, socklen_t addrlen,
                          int backlog);
int create_connected_sock(const struct sockaddr *addr, socklen_t addrlen);

/**
 * ip4: "127.0.0.1:80"
 * ip6: "[...]:80"
 * unix: "unix://path/to/file"
 */
const char *sockaddr_to_str(const struct sockaddr *addr, socklen_t addrlen);
const struct sockaddr *sockaddr_from_str(const char *str,
                                         socklen_t *addrlen_out);

static inline int
set_fd_nonblocking(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) {
        LOG_ERRNO("fcntl(%d, F_GETFL)", fd);
        return -1;
    }
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        LOG_ERRNO("fcntl(%d, F_SETFL, fl | O_NONBLOCK)", fd);
        return -1;
    }
    return 0;
}

static inline uint64_t
now_us()
{
    struct timeval t;
    EXIT_ON_NEG(gettimeofday(&t, NULL));
    return t.tv_sec * 1000000 + t.tv_usec;
}


#endif /* LIB_H_ */
