/*
 * config.h
 *
 *  Created on: Jan 23, 2011
 *      Author: alex
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>

#include "lib.h"

struct configtext {
    const char *drop_to_username;
    const char *drop_to_grpname;
    const char *listen_str;
    const char *pyenv_init_path;
    const char *pyenv_run_func;
    const char *auth_root_uname;
    const char *auth_root_pw;
    const char *client_unauth_timeout_seconds;
    const char *client_auth_fail_timeout_seconds;
    const char *session_noclients_timeout_seconds;
};

struct config {
    uid_t drop_to_uid;
    gid_t drop_to_gid;
    union {
        struct sockaddr listen_addr;
        struct sockaddr_storage listen_addr_storage;
    };
    socklen_t listen_addrlen;
    int listen_backlog;
    const char *pyenv_init_path;
    const char *pyenv_run_func;
    struct auth_entry *auth_entries;
    int nauth_entries;
    int client_root_pw_len;
    int client_unauth_timeout_ticks;
    int client_auth_fail_timeout_ticks;
    int session_noclients_timeout_ticks;
};

extern struct config config;

void config_from_text(const struct configtext *text, struct config *config);

static inline void
config_drop_root(const struct config *config)
{
    drop_to_uid_gid(config->drop_to_uid, config->drop_to_gid);
}

#endif /* CONFIG_H_ */
