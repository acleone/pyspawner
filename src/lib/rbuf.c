/*
 * rbuf.c
 *
 *  Created on: Apr 3, 2011
 *      Author: alex
 */

#include <sys/uio.h>

#include "rbuf.h"

#define RBUF_READ_MAX_IOVCNT    64
#define RBUF_READ_CHUNK_SIZE    (512 - sizeof(struct rbuf))

int
rbuf_read_chunks(EV_P_ int fd, rbuf_read_cb read_cb, void *ctx)
{
    static struct iovec iov[RBUF_READ_MAX_IOVCNT];
    static struct rbuf *rbufs[RBUF_READ_MAX_IOVCNT];

    int i, last_i, last_len, used;
    ssize_t nread;

    /* 1. re-allocate previously used chunks. */
    for (i = 0; i < RBUF_READ_MAX_IOVCNT; i++) {
        if (rbufs[i] != NULL) {
            break;
        }
        if ((rbufs[i] = rbuf_alloc_and_ref(RBUF_READ_CHUNK_SIZE)) == NULL) {
            return -1;
        }
        iov[i].iov_base = rbufs[i]->data;
        iov[i].iov_len = RBUF_READ_CHUNK_SIZE;
    }

    /* 2. readv into chunks. */
 read_again:
    nread = readv(fd, iov, RBUF_READ_MAX_IOVCNT);
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            goto read_again;
        }
        LOG_ERRNO("readv()");
        return -1;
    }
    if (nread == 0) {
        /* EOF - disarm reads. */
        return 1;
    }

    /* 3. determine number of used rbufs. */
    last_i = nread / RBUF_READ_CHUNK_SIZE;
    last_len = nread % RBUF_READ_CHUNK_SIZE;
    if (last_len != 0) {
        /* only used part of chunk - adjust length of last rbuf. */
        rbufs[last_i]->len = last_len;
        used = last_i + 1;
    } else {
        used = last_i;
    }

    /* 4. call callback. */
    read_cb(EV_A_ ctx, rbufs, used, nread);

    /* 5. unref used rbufs. */
    for (i = 0; i < used; i++) {
        rbufs[i] = rbuf_unref(rbufs[i]);
    }
    return 0;
}
