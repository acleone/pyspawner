/*
 * maxfd.h
 *
 *  Created on: Mar 26, 2011
 *      Author: alex
 */

#ifndef MAXFD_H_
#define MAXFD_H_

#include <unistd.h>

#include "def.h"

extern int maxfd;

/**
 * Whenever a new file is opened anywhere, call this.
 */
static inline void
maxfd_update(int fd)
{
    if (fd > maxfd) {
        maxfd = fd;
    }
}

/**
 * Closes all open fds starting with starting_with.
 */
static inline void
maxfd_closeall(int starting_with)
{
    int i;
    /* add a few to maxfd, just in case. */
    for (i = starting_with; i <= maxfd + 3; i++) {
        while (close(i) < 0 && errno != EBADF) {}
    }
}

#endif /* MAXFD_H_ */
