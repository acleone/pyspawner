/*
 * out_q.h
 *
 *  Created on: Mar 22, 2011
 *      Author: alex
 */

#ifndef WRITEQ_H_
#define WRITEQ_H_

#include <stdlib.h>
#include <string.h>

#include "def.h"
#include "queue.h"
#include "rbuf.h"

enum writeq_entry_type {
    WRITEQ_ENTRY_TYPE_RBUF,
    WRITEQ_ENTRY_TYPE_RBUF_SLICE,
    WRITEQ_ENTRY_TYPE_COPY, /**< buffer is in the entry. */
    WRITEQ_ENTRY_TYPE_PTR,
};

struct writeq_entry {
    STAILQ_ENTRY(writeq_entry) q_entry;
    enum writeq_entry_type type;
    uint32_t len;
    union {
        struct rbuf *rbuf;
        struct rbuf_slice slice;
        uint8_t copy_data[0];
        const void *ptr;
    };
};

struct writeq {
    STAILQ_HEAD(, writeq_entry) entries;
    uint32_t nsent;
};

static inline void
writeq_init(struct writeq *q)
{
    STAILQ_INIT(&q->entries);
    q->nsent = 0;
}

void writeq_uninit(struct writeq *q);


/**
 * @return true if the queue is empty.
 */
static inline bool
writeq_is_empty(struct writeq *q)
{
    return STAILQ_EMPTY(&q->entries);
}

/**
 * Append a reference counted buf to the queue. Adds a ref to rbuf.
 */
static inline int
writeq_append_rbuf(struct writeq *q, struct rbuf *rbuf)
{
    struct writeq_entry *entry;

    if (rbuf->len == 0) {
        return 0;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return -1;
    }
    entry->type = WRITEQ_ENTRY_TYPE_RBUF;
    entry->len = rbuf->len;
    entry->rbuf = rbuf_add_ref(rbuf);
    STAILQ_INSERT_TAIL(&q->entries, entry, q_entry);
    return 0;
}

/**
 * Append a copy of slice the queue.  Adds a ref to the rbuf pointed to by
 * the slice.
 */
static inline int
writeq_append_rbuf_slice(struct writeq *q, struct rbuf_slice *slice)
{
    struct writeq_entry *entry;

    if (slice->len == 0) {
        return 0;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return -1;
    }
    entry->type = WRITEQ_ENTRY_TYPE_RBUF_SLICE;
    entry->len = slice->len;
    entry->slice.rbuf = rbuf_add_ref(slice->rbuf);
    entry->slice.offset = slice->offset;
    entry->slice.len = slice->len;
    STAILQ_INSERT_TAIL(&q->entries, entry, q_entry);
    return 0;
}

/**
 * Append a copy of buf the queue.
 */
static inline int
writeq_append_copy(struct writeq *q, const void *buf, uint32_t len)
{
    struct writeq_entry *entry;

    if (len == 0) {
        return 0;
    }

    if ((entry = malloc(sizeof(*entry) + len)) == NULL) {
        return -1;
    }
    entry->type = WRITEQ_ENTRY_TYPE_COPY;
    entry->len = len;
    memcpy(entry->copy_data, buf, len);
    STAILQ_INSERT_TAIL(&q->entries, entry, q_entry);
    return 0;
}

/**
 * Append a ptr to the queue.  The ptr data must be vaild while
 * it's in the queue.
 */
static inline int
writeq_append_ptr(struct writeq *q, const void *ptr, uint32_t len)
{
    struct writeq_entry *entry;

    if (len == 0) {
        return 0;
    }

    if ((entry = malloc(sizeof(*entry))) == NULL) {
        return -1;
    }
    entry->type = WRITEQ_ENTRY_TYPE_PTR;
    entry->len = len;
    entry->ptr = ptr;
    STAILQ_INSERT_TAIL(&q->entries, entry, q_entry);
    return 0;
}

/**
 * Writes elements to fd, and removes written elements.
 * @return -1 on error, otherwise 0.
 */
int writeq_write(struct writeq *q, int fd);


#endif /* WRITEQ_H_ */
