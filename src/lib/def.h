/*
 * def.h
 *
 *  Created on: Feb 19, 2011
 *      Author: alex
 */

#ifndef DEF_H_
#define DEF_H_

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h>
#include <errno.h>
#include <error.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


enum io_priorities {
    IOP_SIGINT,
    IOP_SIGCHILD,
    IOP_LISTEN,
    IOP_CLIENT,

    IOP_LAST,
};

#define MAX(x, y) ( ((x) >= (y))? (x) : (y) )
#define MIN(x, y) ( ((x) <= (y))? (x) : (y) )

#ifndef __PACKED
#define __PACKED __attribute__((packed))
#endif

#ifndef __THREAD
#define __THREAD __thread
#endif

#define atomic_inc(ptr) __sync_add_and_fetch(ptr, 1)
#define atomic_dec(ptr) __sync_sub_and_fetch(ptr, 1)

#define CONTAINER_OF(p, type, field) \
    (type *)(((char *)p) - offsetof(type, field))

#define ASSERT(x)                                                              \
    do {                                                                       \
        if (!(x)) {                                                            \
            error_at_line(EXIT_FAILURE, 0, __FILE__, __LINE__, #x);            \
        }                                                                      \
    } while (0)

#define ASSERT_NOT_REACHED() ASSERT(0)

#ifndef LOG_LEVEL
#define LOG_LEVEL   0
#endif

#define DEBUGF(lvl, fmt...)                                                    \
    do { if (lvl <= LOG_LEVEL) {                                               \
        printf("%s:%d: ", __func__, __LINE__);                                              \
        printf(fmt);                                                           \
    } } while (0)

#define LOGF(lvl, fmt...)                                                      \
    do { if (lvl <= LOG_LEVEL) {                                               \
        printf(fmt);                                                           \
    } } while (0)

#define LOGIF(lvl)  if (lvl <= LOG_LEVEL)

#define LOG_ERRNO(fmt...)                                                      \
    error_at_line(0, errno, __FILE__, __LINE__, ##fmt)

/**
 * Logs error and calls exit(EXIT_FAILURE) if rc < 0.
 */
#define EXIT_ON_NEG(rc)                                                        \
    do {                                                                       \
        if ((rc) < 0) {                                                        \
            error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__, #rc);       \
        }                                                                      \
    } while (0)

#define EXIT_ON_NEG_FMT(rc, fmt...)                                            \
    do {                                                                       \
        if ((rc) < 0) {                                                        \
            error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,             \
                          ##fmt);                                              \
        }                                                                      \
    } while (0)

#define EXIT_ON_NULL(rc)                                                       \
    do {                                                                       \
        if ((rc) == NULL) {                                                    \
            error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__, #rc);       \
        }                                                                      \
    } while (0)

#define EXIT_ON_NULL_FMT(rc, fmt...)                                           \
    do {                                                                       \
        if ((rc) == NULL) {                                                    \
            error_at_line(EXIT_FAILURE, errno, __FILE__, __LINE__,             \
                          ##fmt);                                              \
        }                                                                      \
    } while (0)

#define EXIT_ON_PTERR(rc)                                                      \
    do {                                                                       \
        if ((rc) != 0) {                                                       \
            error_at_line(EXIT_FAILURE, rc, __FILE__, __LINE__, #rc);          \
        }                                                                      \
    } while (0)

#define betoh16     be16toh
#define letoh16     le16toh
#define betoh32     be32toh
#define letoh32     le32toh
#define betoh64     be64toh
#define letoh64     le64toh



#endif /* DEF_H_ */
