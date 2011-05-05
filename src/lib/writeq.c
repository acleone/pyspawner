/*
 * out_q.c
 *
 *  Created on: Mar 22, 2011
 *      Author: alex
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/uio.h>

#include "lib.h"
#include "writeq.h"

#define WRITEQ_MAX_IOVCNT  64

void
writeq_entry_free(struct writeq_entry *entry)
{
    if (entry->type == WRITEQ_ENTRY_TYPE_RBUF) {
        entry->rbuf = rbuf_release(entry->rbuf);
    } else if (entry->type == WRITEQ_ENTRY_TYPE_RBUF_SLICE) {
        rbuf_slice_uninit(&entry->slice);
    }
    free(entry);
}

void
writeq_uninit(struct writeq *q)
{
    struct writeq_entry *entry, *next;
    STAILQ_FOREACH_SAFE(entry, &q->entries, q_entry, next) {
        writeq_entry_free(entry);
    }
}

static inline void *
writeq_entry_iov_base(struct writeq_entry *entry, uint32_t nsent)
{
    switch (entry->type) {
    case WRITEQ_ENTRY_TYPE_RBUF:
        return &entry->rbuf->data[nsent];
    case WRITEQ_ENTRY_TYPE_RBUF_SLICE:
        return rbuf_slice_buf(&entry->slice) + nsent;
    case WRITEQ_ENTRY_TYPE_COPY:
        return &entry->copy_data[nsent];
    case WRITEQ_ENTRY_TYPE_PTR:
        return (void *)(entry->ptr + nsent);
    }
    ASSERT_NOT_REACHED();
    return NULL;
}

int
writeq_write(struct writeq *q, int fd)
{
    static __THREAD struct iovec iov[WRITEQ_MAX_IOVCNT];

    struct writeq_entry *entry;
    int i, iovcnt;
    ssize_t nsent;

    while (!writeq_is_empty(q)) {
        // 1. build the iovec from entries in the queue.
        // the very first iovec might be only part of the first buffer.
        entry = STAILQ_FIRST(&q->entries);
        iov[0].iov_base = (void *)writeq_entry_iov_base(entry, q->nsent);
        iov[0].iov_len = entry->len - q->nsent;
        i = 1;
        while (i < WRITEQ_MAX_IOVCNT &&
                (entry = STAILQ_NEXT(entry, q_entry)) != NULL) {
            iov[i].iov_base = (void *)writeq_entry_iov_base(entry, 0);
            iov[i].iov_len = entry->len;
            i++;
        }
        iovcnt = i;

        // 2. actually send the data.
        nsent = writev(fd, iov, iovcnt);
        if (nsent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return 0;
            }
            LOG_ERRNO("writev()");
            return -1;
        }
        LOGIF(15) {
            printf("< %d wrote %d bytes: ", fd, nsent);
            print_iov_repr(stdout, iov, nsent);
            printf("\n");
        }

        // 3. remove entries that were completely sent.
        q->nsent += nsent;
        do {
            entry = STAILQ_FIRST(&q->entries);
            if (q->nsent < entry->len) {
                // need to write more.
                return 0;
            }
            q->nsent -= entry->len;
            STAILQ_REMOVE_HEAD(&q->entries, q_entry);
            writeq_entry_free(entry);
        } while (q->nsent > 0);
    }
    // the queue is now empty.
    return 0;
}
