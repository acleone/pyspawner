/*
 * auth.h
 *
 *  Created on: May 3, 2011
 *      Author: alex
 */

#ifndef AUTH_H_
#define AUTH_H_

#include "queue.h"

#define AUTH_NONCE_LEN      32
#define AUTH_MAX_UNAME_LEN  32
#define AUTH_MAX_PW_LEN     32

struct auth_entry {
    SLIST_ENTRY(auth_entry) next;
    char uname[AUTH_MAX_UNAME_LEN];
    char pw[AUTH_MAX_PW_LEN];
    int uname_len;
    int pw_len;
    bool is_admin;
};

int auth_add_entry(const char *uname, const char *pw, bool is_admin);

/**
 * @return -1 on error, otherwise 0.
 */
int auth_get_nonce(uint8_t *nonce_out);

struct rbuf;

/**
 * @return a pointer to the auth_entry if successfully authed.
 */
struct auth_entry *auth_client(const uint8_t *nonce, const struct rbuf *body);


#endif /* AUTH_H_ */
