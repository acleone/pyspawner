/*
 * config.cpp
 *
 *  Created on: Jan 23, 2011
 *      Author: alex
 */

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "def.h"
#include "lib.h"
#include "auth.h"
#include "config.h"
#include "tick.h"

void
config_from_text(const struct configtext *text, struct config *config)
{
    const struct sockaddr *addr;
    names_to_uid_gid(text->drop_to_username, text->drop_to_grpname,
                     &config->drop_to_uid, &config->drop_to_gid);
    addr = sockaddr_from_str(text->listen_str, &config->listen_addrlen);
    if (addr == NULL) {
        printf("Error converting \"%s\" to sockaddr.\n", text->listen_str);
        exit(EXIT_FAILURE);
    }
    memcpy(&config->listen_addr, addr, config->listen_addrlen);
    config->listen_backlog = 64;
    config->pyenv_init_path = text->pyenv_init_path;
    config->pyenv_run_func = text->pyenv_run_func;

    EXIT_ON_NULL(config->auth_entries = calloc(1, sizeof(struct auth_entry)));
    config->nauth_entries = 1;
    config->auth_entries[0].uname_len = strlen(text->auth_root_uname);
    config->auth_entries[0].pw_len    = strlen(text->auth_root_pw);
    ASSERT(config->auth_entries[0].uname_len < AUTH_MAX_UNAME_LEN);
    ASSERT(config->auth_entries[0].pw_len    < AUTH_MAX_PW_LEN);
    strcpy(config->auth_entries[0].uname, text->auth_root_uname);
    strcpy(config->auth_entries[0].pw,    text->auth_root_pw);

    config->client_unauth_timeout_ticks =
            ceil(atof(text->client_unauth_timeout_seconds) * TICKS_PER_SEC);
    ASSERT(config->client_unauth_timeout_ticks > 0);
    LOGF(3, "config client_unauth_timeout_ticks=%d\n",
         config->client_unauth_timeout_ticks);
    config->client_auth_fail_timeout_ticks =
            ceil(atof(text->client_auth_fail_timeout_seconds) * TICKS_PER_SEC);
    ASSERT(config->client_auth_fail_timeout_ticks > 0);
    LOGF(3, "config client_auth_fail_timeout_ticks=%d\n",
         config->client_auth_fail_timeout_ticks);
    config->session_noclients_timeout_ticks =
            ceil(atof(text->session_noclients_timeout_seconds) * TICKS_PER_SEC);
    ASSERT(config->session_noclients_timeout_ticks > 0);
    LOGF(3, "config session_noclients_timeout_ticks=%d\n",
         config->session_noclients_timeout_ticks);
}
