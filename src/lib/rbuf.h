/*
 * rbuf.h
 *
 *  Created on: Mar 24, 2011
 *      Author: alex
 */

#ifndef RBUF_H_
#define RBUF_H_

#include <ev.h>

#include "def.h"
#include "queue.h"

/* ref counted buf */
struct rbuf {
    uint16_t len; /**< bytes of data. */
    uint16_t refcount;
    uint8_t data[0];
};

struct rbuf_slice {
    struct rbuf *rbuf;
    uint16_t offset;
    uint16_t len;
};

static inline struct rbuf *
rbuf_alloc_and_ref(uint16_t len)
{
    struct rbuf *rbuf;

    if ((rbuf = malloc(sizeof(*rbuf) + len)) == NULL) {
        return NULL;
    }
    rbuf->len = len;
    rbuf->refcount = 1;
    return rbuf;
}

static inline struct rbuf *
rbuf_add_ref(struct rbuf *rbuf)
{
    rbuf->refcount++;
    return rbuf;
}

/**
 * Returns NULL.
 * Get in the habit of writing:
 * struct rbuf *x;
 * x = rbuf_alloc_and_ref(2);
 * x = rbuf_release(x);
 */
static inline struct rbuf *
rbuf_release(struct rbuf *rbuf)
{
    ASSERT(rbuf->refcount > 0);

    rbuf->refcount--;
    if (rbuf->refcount == 0) {
        /* no more references, free the buf. */
        free(rbuf);
    }
    return NULL;
}

/**
 * Increments rbuf refcount. uninit with rbuf_slice_uninit when done.
 */
static inline void
rbuf_get_slice_init(struct rbuf *rbuf, struct rbuf_slice *slice,
                    uint16_t offset, uint16_t len)
{
    slice->rbuf = rbuf_add_ref(rbuf);
    slice->offset = offset;
    slice->len = len;
}

static inline void
rbuf_slice_uninit(struct rbuf_slice *slice)
{
    slice->rbuf = rbuf_release(slice->rbuf);
}

/**
 * Creates a new slice that references rbuf.
 * Increments rbuf refcount.  free with rbuf_slice_free.
 */
static inline struct rbuf_slice *
rbuf_get_slice(struct rbuf *rbuf, uint16_t offset, uint16_t len)
{
    struct rbuf_slice *slice;

    if ((slice = malloc(sizeof(*slice))) == NULL) {
        return NULL;
    }
    rbuf_get_slice_init(rbuf, slice, offset, len);
    return slice;
}

static inline void
rbuf_slice_free(struct rbuf_slice *slice)
{
    rbuf_slice_uninit(slice);
    free(slice);
}

static inline uint8_t *
rbuf_slice_buf(struct rbuf_slice *slice)
{
    ASSERT(slice->rbuf != NULL);
    return &slice->rbuf->data[slice->offset];
}


typedef void (*rbuf_read_cb)(EV_P_ void *ctx, struct rbuf **rbufs,
                             int nrbufs, uint16_t nbytes);
/**
 * Reads up to roughly UINT16_MAX bytes into fixed-size rbufs,
 * then calls rbuf_read_cb.  The reason this function takes a callback
 * is that the used rbuf's need to be unref-ed after the callback.
 * Note: NOT THREAD SAFE.
 * @return -1 on error, 1 on EOF, 0 otherwise.
 */
int rbuf_read_chunks(EV_P_ int fd, rbuf_read_cb read_cb, void *ctx);

#endif /* RBUF_H_ */
