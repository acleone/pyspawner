/*
 * lib.c
 *
 *  Created on: Feb 21, 2011
 *      Author: alex
 */

#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "def.h"
#include "lib.h"

#define SOCKADDR_STR_SIZE   (MAX(INET6_ADDRSTRLEN, 108) + 20)


void
print_repr(FILE *f, const void *str, int len, bool with_quotes)
{
    int i;
    if (with_quotes) {
        putc('"', f);
    }
    for (i = 0; i < len; i++) {
        char c = ((const char *)str)[i];
        switch (c) {
        case '\t': putc('\\', f); putc('t' , f); break;
        case '\n': putc('\\', f); putc('n' , f); break;
        case '\r': putc('\\', f); putc('r' , f); break;
        case ' ' : putc(' ' , f); break;
        case '"' : putc('\\', f); putc('"' , f); break;
        case '\\': putc('\\', f); putc('\\', f); break;
        default:
            if (isgraph(c)) {
                putc(c, f);
            }
            else {
                fprintf(f, "\\x%02x", (uint8_t)c);
            }
        }
    }
    if (with_quotes) {
        putc('"', f);
    }
}

void
print_iov_repr(FILE *f, const struct iovec *iov, int nbytes)
{
    int i;
    putc('"', f);
    for (i = 0; nbytes > 0; i++) {
        print_repr(f, iov[i].iov_base, MIN(nbytes, iov[i].iov_len), false);
        nbytes -= iov[i].iov_len;
    }
    putc('"', f);
}

void
names_to_uid_gid(const char *usrname, const char *grpname, uid_t *uid_out,
                 gid_t *gid_out)
{
    struct passwd *u;
    struct group *g;

    u = getpwnam(usrname);
    EXIT_ON_NULL_FMT(u, "getpwnam(\"%s\")", usrname);
    *uid_out = u->pw_uid;

    g = getgrnam(grpname);
    EXIT_ON_NULL_FMT(g, "getgrnam(\"%s\")", grpname);
    *gid_out = g->gr_gid;
}

void
drop_to_uid_gid(uid_t uid, gid_t gid)
{
    EXIT_ON_NEG_FMT(setgid(gid), "setgid(%d)", gid);
    EXIT_ON_NEG_FMT(setuid(uid), "setuid(%d)", uid);
}

void
raise_rlimit(int new_limit)
{
    struct rlimit rlimit;
    EXIT_ON_NEG(getrlimit(RLIMIT_NOFILE, &rlimit));
    LOGF(0, "Raising current fd limit of (%d, %d) to (%d, %d)\n",
         (int)rlimit.rlim_cur, (int)rlimit.rlim_max, new_limit, new_limit);
    rlimit.rlim_cur = rlimit.rlim_max = new_limit;
    if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
        if (errno == EPERM) {
            LOGF(0, "Could not raise rlimit - not root.\n");
            return;
        }
        EXIT_ON_NEG_FMT(-1, "setrlimit()");
    }
}

int
create_listening_sock(const struct sockaddr *addr, socklen_t addrlen,
                      int backlog)
{
    int fd, on = 1;

    EXIT_ON_NEG(fd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK |
                            SOCK_CLOEXEC, 0));
    EXIT_ON_NEG(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)));
    EXIT_ON_NEG(bind(fd, addr, addrlen));
    EXIT_ON_NEG(listen(fd, backlog));
    return fd;
}

int
create_connected_sock(const struct sockaddr *addr, socklen_t addrlen)
{
    int fd;

    EXIT_ON_NEG(fd = socket(addr->sa_family, SOCK_STREAM, 0));
    if (connect(fd, addr, addrlen) < 0) {
        LOG_ERRNO("connect()");
        exit(EXIT_FAILURE);
    }
    EXIT_ON_NEG(set_fd_nonblocking(fd));
    return fd;
}



static const char *
sockaddr_to_str_ip4(const struct sockaddr *addr, socklen_t addrlen,
                    char ret[SOCKADDR_STR_SIZE])
{
    const struct sockaddr_in *ip4 = (const struct sockaddr_in *)addr;
    const void *src = &ip4->sin_addr;
    int port = ntohs(ip4->sin_port);
    int retlen;

    if (inet_ntop(AF_INET, src, ret, addrlen) == NULL) {
        LOG_ERRNO("inet_ntop()");
        return NULL;
    }
    retlen = strnlen(ret, SOCKADDR_STR_SIZE);
    if (snprintf(ret + retlen, SOCKADDR_STR_SIZE - retlen, ":%d", port) < 0) {
        LOG_ERRNO("snprintf()");
        return NULL;
    }
    return ret;
}

static const char *
sockaddr_to_str_ip6(const struct sockaddr *addr, socklen_t addrlen,
                    char ret[SOCKADDR_STR_SIZE])
{
    const struct sockaddr_in6 *ip6 = (const struct sockaddr_in6 *)addr;
    const void *src = &ip6->sin6_addr;
    int port = ntohs(ip6->sin6_port);
    int retlen;

    ret[0] = '[';
    if (inet_ntop(AF_INET6, src, ret + 1, addrlen) == NULL) {
        return NULL;
    }
    retlen = strnlen(ret, SOCKADDR_STR_SIZE);
    ret[retlen] = ']';
    retlen++;
    if (snprintf(ret + retlen, SOCKADDR_STR_SIZE - retlen, ":%d", port) < 0) {
        return NULL;
    }
    return ret;
}

static const char *
sockaddr_to_str_unix(const struct sockaddr *addr, socklen_t addrlen,
                     char ret[SOCKADDR_STR_SIZE])
{
    const struct sockaddr_un *un = (const struct sockaddr_un *)addr;
    if (snprintf(ret, SOCKADDR_STR_SIZE, "unix://%s", un->sun_path) < 0) {
        return NULL;
    }
    return ret;
}

const char *
sockaddr_to_str(const struct sockaddr *addr, socklen_t addrlen)
{
    static char ret[SOCKADDR_STR_SIZE];

    if (addr->sa_family == AF_INET) {
        return sockaddr_to_str_ip4(addr, addrlen, ret);
    } else if (addr->sa_family == AF_INET6) {
        return sockaddr_to_str_ip6(addr, addrlen, ret);
    } else if (addr->sa_family == AF_UNIX) {
        return sockaddr_to_str_unix(addr, addrlen, ret);
    }
    DEBUGF(1, "unknown af=%d\n", addr->sa_family);
    return NULL;
}

const struct sockaddr *
sockaddr_from_str_ip4(const char *str, socklen_t *addrlen_out,
                      struct sockaddr_storage *addr)
{
    char addrstr[INET_ADDRSTRLEN + 1];
    struct sockaddr_in *ip4 = (struct sockaddr_in *)addr;
    char *colon;
    int addrstrlen;
    uint16_t port;
    memset(addr, 0, sizeof(*ip4));
    if ((colon = strchr(str, ':')) == NULL) {
        return NULL;
    }
    addrstrlen = colon - str;
    if (addrstrlen >= sizeof(addrstr)) {
        return NULL;
    }
    memcpy(addrstr, str, addrstrlen);
    addrstr[addrstrlen] = '\0';

    if (inet_pton(AF_INET, addrstr, &ip4->sin_addr) != 1) {
        return NULL;
    }
    if (sscanf(colon + 1, "%hd", &port) != 1) {
        return NULL;
    }
    ip4->sin_family = AF_INET;
    ip4->sin_port = htons(port);
    *addrlen_out = sizeof(*ip4);
    return (struct sockaddr *)ip4;
}

const struct sockaddr *
sockaddr_from_str_ip6(const char *str, socklen_t *addrlen_out,
                      struct sockaddr_storage *addr)
{
    char addrstr[INET6_ADDRSTRLEN + 1];
    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)addr;
    char *colon;
    int addrstrlen;
    uint16_t port;
    memset(addr, 0, sizeof(*ip6));
    if ((colon = strchr(str, ':')) == NULL) {
        return NULL;
    }
    if (colon == str || colon[-1] != ']') {
        return NULL;
    }
    addrstrlen = colon - (str + 1);
    if (addrstrlen >= sizeof(addrstr)) {
        return NULL;
    }
    memcpy(addrstr, str + 1, addrstrlen);
    addrstr[addrstrlen] = '\0';

    if (inet_pton(AF_INET6, addrstr, &ip6->sin6_addr) != 1) {
        return NULL;
    }
    if (sscanf(colon + 1, "%hd", &port) != 1) {
        return NULL;
    }
    ip6->sin6_family = AF_INET6;
    ip6->sin6_port = htons(port);
    *addrlen_out = sizeof(*ip6);
    return (struct sockaddr *)ip6;
}

const struct sockaddr *
sockaddr_from_str_unix(const char *str, socklen_t *addrlen_out,
                       struct sockaddr_storage *addr)
{
    struct sockaddr_un *un = (struct sockaddr_un *)addr;
    memset(addr, 0, sizeof(*un));
    if (snprintf(un->sun_path, sizeof(un->sun_path), "%s",
                 str + strlen("unix://")) < 0) {
        return NULL;
    }
    un->sun_family = AF_UNIX;
    *addrlen_out = offsetof(struct sockaddr_un, sun_path) +
                   strlen(un->sun_path) + 1;
    return (struct sockaddr *)un;
}


const struct sockaddr *
sockaddr_from_str(const char *str, socklen_t *addrlen_out)
{
    static struct sockaddr_storage addr;
    if (strncmp(str, "unix://", strlen("unix://")) == 0) {
        return sockaddr_from_str_unix(str, addrlen_out, &addr);
    } else if (str[0] == '[') {
        return sockaddr_from_str_ip6(str, addrlen_out, &addr);
    } else {
        return sockaddr_from_str_ip4(str, addrlen_out, &addr);
    }
}
