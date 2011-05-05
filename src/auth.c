/*
 * auth.c
 *
 *  Created on: May 3, 2011
 *      Author: alex
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <sha2.h>
#include <string.h>
#include <unistd.h>

#include "def.h"
#include "auth.h"
#include "config.h"
#include "maxfd.h"
#include "rbuf.h"

static SLIST_HEAD(, auth_entry) auth_entries;
static int random_fd = -1;
static const char *random_path = "/dev/urandom";
static const int random_flags = O_CLOEXEC | O_RDONLY;

int
auth_add_entry(const char *uname, const char *pw, bool is_admin)
{
    struct auth_entry *entry = NULL;
    if ((entry = malloc(sizeof(*entry))) == NULL) {
        goto fail;
    }
    memset(entry, 0, sizeof(*entry));
    entry->uname_len = strlen(uname);
    entry->pw_len = strlen(pw);
    if ((entry->uname_len >= AUTH_MAX_UNAME_LEN) ||
            (entry->pw_len >= AUTH_MAX_PW_LEN)) {
        goto fail;
    }
    memcpy(entry->uname, uname, entry->uname_len);
    memcpy(entry->pw, pw, entry->pw_len);
    entry->is_admin = is_admin;
    SLIST_INSERT_HEAD(&auth_entries, entry, next);
    return 0;
 fail:
    if (entry != NULL) {
        free(entry);
    }
    return -1;
}

int
auth_get_nonce(uint8_t *nonce_out)
{
    ssize_t nbytes = read(random_fd, nonce_out, AUTH_NONCE_LEN);
    if (nbytes != AUTH_NONCE_LEN) {
        LOG_ERRNO("read()");
        return -1;
    }
    return 0;
}

struct auth_entry *
auth_client(const uint8_t *nonce, const struct rbuf *body)
{
    SHA256_CTX sctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    const char *body_uname = (const char *)body->data;
    const uint8_t *body_digest;
    struct auth_entry *entry;
    int i, r, uname_len;

    uname_len = strnlen(body_uname, body->len);
    if (body->len != uname_len + 1 + SHA256_DIGEST_LENGTH) {
        DEBUGF(3, "bad auth reply len=%d\n", body->len);
        return NULL;
    }

    SLIST_FOREACH(entry, &auth_entries, next) {
        if ((uname_len == entry->uname_len) &&
                (memcmp(entry->uname, body_uname, entry->uname_len) == 0)) {
            goto found;
        }
    }
    DEBUGF(3, "unknown uname=\"%s\"\n", body_uname);
    return NULL;

 found:
    body_digest = &body->data[uname_len + 1];
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, nonce, AUTH_NONCE_LEN);
    SHA256_Update(&sctx, (const uint8_t *)entry->pw, entry->pw_len);
    SHA256_Final(digest, &sctx);

    /* compare each byte instead of using memcmp to prevent timing attacks. */
    r = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        r |= (body_digest[i] ^ digest[i]);
    }
    if (r != 0) {
        DEBUGF(3, "digest doesn't match\n");
        return NULL;
    }
    return entry;
}

void
auth_sysinit(EV_P)
{
    SLIST_INIT(&auth_entries);
    EXIT_ON_NEG(random_fd = open(random_path, random_flags));
    maxfd_update(random_fd);
}

void
auth_sysuninit(EV_P)
{
    close(random_fd);
}
