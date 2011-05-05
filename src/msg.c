/*
 * msg.c
 *
 *  Created on: Apr 4, 2011
 *      Author: alex
 */

#include <stdlib.h>
#include <unistd.h>

#include "lib.h"
#include "msg.h"

#define _STR(x) [x] = #x
static const char * const
MSG_TYPE_TO_STR[MSG_TYPE_LAST] = {
    _STR(MSG_TYPE_SUCCESS),
    _STR(MSG_TYPE_ERROR),
    _STR(MSG_TYPE_AUTH_NONCE),
    _STR(MSG_TYPE_AUTH_PW_REPLY),
    _STR(MSG_TYPE_START_SESSION),
    _STR(MSG_TYPE_JOIN_SESSION),
    _STR(MSG_TYPE_LEAVE_SESSION),
    _STR(MSG_TYPE_START_WORKER),
    _STR(MSG_TYPE_SIGNAL_WORKER),
    _STR(MSG_TYPE_WORKER_STDIN),
    _STR(MSG_TYPE_WORKER_MSGIN),
    _STR(MSG_TYPE_SESSION_ENDED),
    _STR(MSG_TYPE_WORKER_EXITED),
    _STR(MSG_TYPE_WORKER_STDOUT),
    _STR(MSG_TYPE_WORKER_STDERR),
    _STR(MSG_TYPE_WORKER_MSGOUT),
    _STR(MSG_TYPE_PIPE_ERROR),
};
#undef _STR

const char *
msg_type_to_str(uint16_t type)
{
    static char buf[25];
    if (type >= MSG_TYPE_LAST) {
        sprintf(buf, "%d", type);
        return buf;
    }
    return MSG_TYPE_TO_STR[type];
}

enum msg_rx_rc
msg_rx_read1(struct msg_rx *rx, int fd)
{
    struct msg_hdr * const hdr = &rx->hdr;
    ssize_t nread;

    switch (rx->state) {
    case MSG_RX_STATE_READING_HDR:
 read_hdr:
        nread = read(fd, &rx->hdr_buf[rx->offset], MSG_HDR_LEN - rx->offset);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MSG_RX_RC_NEED_MORE;
            }
            if (errno == EINTR) {
                goto read_hdr;
            }
            LOG_ERRNO("read()");
            return MSG_RX_RC_ERROR;
        }
        LOGIF(15) {
            printf("> %d read %d bytes: ", fd, nread);
            print_repr(stdout, &rx->hdr_buf[rx->offset], nread, true);
            printf("\n");
        }
        if (nread == 0) {
            return MSG_RX_RC_EOF;
        }
        rx->offset += nread;
        if (rx->offset < MSG_HDR_LEN) {
            return MSG_RX_RC_NEED_MORE;
        }
        if (msg_hdr_from_buf(rx->hdr_buf, hdr) < 0) {
            LOGF(1, "E %d Bad message checksum.\n", fd);
            return MSG_RX_RC_BAD_HDR_CHKSUM;
        }
        if (rx->body != NULL) {
            rx->body = rbuf_release(rx->body);
        }
        rx->body = rbuf_alloc_and_ref(hdr->len);
        if (rx->body == NULL) {
            return MSG_RX_RC_ERROR;
        }
        rx->state = MSG_RX_STATE_READING_BODY;
        rx->offset = 0;
        if (hdr->len == 0) {
            goto body_done;
        }
        // FALLTHROUGH
    case MSG_RX_STATE_READING_BODY:
 read_body:
        nread = read(fd, &rx->body->data[rx->offset], hdr->len - rx->offset);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MSG_RX_RC_NEED_MORE;
            }
            if (errno == EINTR) {
                goto read_body;
            }
            LOG_ERRNO("read()");
            return MSG_RX_RC_ERROR;
        }
        LOGIF(15) {
            printf("> %d read %d bytes: ", fd, nread);
            print_repr(stdout, &rx->body->data[rx->offset], nread, true);
            printf("\n");
        }
        if (nread == 0) {
            return MSG_RX_RC_EOF;
        }
        rx->offset += nread;
        if (rx->offset < hdr->len) {
            return MSG_RX_RC_NEED_MORE;
        }
 body_done:
        rx->state = MSG_RX_STATE_READING_HDR;
        rx->offset = 0;
    }
    return MSG_RX_RC_GOT_MSG;
}
