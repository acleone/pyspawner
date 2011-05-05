#include <ev.h>
#include <signal.h>
#include <stdio.h>

#include "def.h"
#include "lib.h"
#include "auth.h"
#include "config.h"

extern void auth_sysinit(EV_P);
extern void auth_sysuninit(EV_P);
extern void tick_sysinit(EV_P);
extern void tick_sysuninit(EV_P);
extern void server_sysinit(EV_P);
extern void server_sysuninit(EV_P);
extern void client_sysinit(EV_P);
extern void client_sysuninit(EV_P);
extern void session_sysinit(EV_P);
extern void session_sysuninit(EV_P);
extern void pyenv_sysinit(EV_P);
extern void pyenv_sysuninit(EV_P);

struct config config;

ev_signal sigint_watcher;

static void
sigint_cb(EV_P_ ev_signal *w, int revents)
{
    printf("\nCaught SIGINT, exiting...\n");
    ev_break(EV_A_ EVBREAK_ALL);
}

int
main(int argc, char **argv)
{
    struct configtext text = {
        .drop_to_username = "alex",
        .drop_to_grpname = "alex",
        .listen_str = "127.0.0.1:8046",
//        .listen_str = "unix://test-unix-socket",
        .pyenv_init_path = "src/python/init.py",
        .pyenv_run_func = "run",
        .auth_root_uname = "admin",
        .auth_root_pw = "admin",
        .client_unauth_timeout_seconds = "10.0",
        .client_auth_fail_timeout_seconds = "2.0",
        .session_noclients_timeout_seconds = "60.0",
    };
    int i;
    config_from_text(&text, &config);

    if (!ev_default_loop(0)) {
        printf("libev initialization error!\n");
        return 1;
    }

    raise_rlimit(80000);

    printf("Starting pyspawner pid=%d\n", getpid());
    printf("Listening on %s\n", sockaddr_to_str(&config.listen_addr,
                                                config.listen_addrlen));
    auth_sysinit(EV_A);
    for (i = 0; i < config.nauth_entries; i++) {
        EXIT_ON_NEG(auth_add_entry(config.auth_entries[i].uname,
                                   config.auth_entries[i].pw,
                                   config.auth_entries[i].is_admin));
    }
    tick_sysinit(EV_A);
    server_sysinit(EV_A);
    client_sysinit(EV_A);
    session_sysinit(EV_A);
    config_drop_root(&config);
    pyenv_sysinit(EV_A);

    ev_signal_init(&sigint_watcher, sigint_cb, SIGINT);
    ev_signal_start(EV_A_ &sigint_watcher);

    ev_run(EV_A_ 0);

    ev_signal_stop(EV_A_ &sigint_watcher);

	pyenv_sysuninit(EV_A);
	session_sysuninit(EV_A);
	client_sysuninit(EV_A);
	server_sysuninit(EV_A);
	tick_sysuninit(EV_A);
	auth_sysuninit(EV_A);

	if (config.listen_addr.sa_family == AF_UNIX) {
	    // unlink the socket file
	    struct sockaddr_un *un = (struct sockaddr_un *)&config.listen_addr;
	    LOGF(0, "Removing \"%s\"\n", un->sun_path);
	    EXIT_ON_NEG(unlink(un->sun_path));
	}

	return 0;
}
