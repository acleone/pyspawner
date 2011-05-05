/*
 * msg.h
 *
 *  Created on: Feb 26, 2011
 *      Author: alex
 */

#ifndef MSG_H_
#define MSG_H_

#include <string.h>

#include "def.h"
#include "queue.h"
#include "rbuf.h"

#define MSG_HDR_LEN (2 + 1 + 1 + 2 + 2)

struct msg_hdr {
    uint16_t type;
    uint8_t sid;
    union {
        uint8_t byte;
        struct {
            bool f_more : 1;
        };
    } flags;
    uint16_t len; /**< number of bytes following the header. */
    uint16_t csum;
};

enum msg_type {
    MSG_TYPE_SUCCESS,
    MSG_TYPE_ERROR, // errstr

    MSG_TYPE_AUTH_NONCE, // nonce str
    MSG_TYPE_AUTH_PW_REPLY, // uid byte + sha256 digest

    /* authed clients: */

    MSG_TYPE_START_SESSION,
    // success: uint32_t sessid

    MSG_TYPE_JOIN_SESSION, // uint32_t le sessid
    // success:

    MSG_TYPE_LEAVE_SESSION,
    // success:

    MSG_TYPE_START_WORKER,
    // success: uint32_t le pid

    MSG_TYPE_SIGNAL_WORKER, // uint32_t le signum
    // success:


    MSG_TYPE_WORKER_STDIN, // bytes, len=0 for EOF
    // success:

    MSG_TYPE_WORKER_MSGIN, // bytes, len=0 for EOF
    // success:


    MSG_TYPE_SESSION_ENDED,
    MSG_TYPE_WORKER_EXITED, // exit status int32_t le

    MSG_TYPE_WORKER_STDOUT, // bytes, len=0 for EOF
    MSG_TYPE_WORKER_STDERR, // bytes, len=0 for EOF
    MSG_TYPE_WORKER_MSGOUT, // bytes, len=0 for EOF

    MSG_TYPE_PIPE_ERROR, // int32 le: MSG_TYPE_WORKER_* which pipe errored

    MSG_TYPE_LAST,
};

const char *msg_type_to_str(uint16_t type);

static inline uint16_t
msg_hdr_csum(const uint8_t buf[MSG_HDR_LEN])
{
    uint16_t r = buf[0] + buf[1] + buf[2] + buf[3]
               + buf[4] + buf[5];
    return ~r;
}

static inline void
msg_hdr_to_buf(const struct msg_hdr *hdr, uint8_t buf[MSG_HDR_LEN])
{
    buf[0] = hdr->type;
    buf[1] = (hdr->type >> 8);
    buf[2] = hdr->sid;
    buf[3] = hdr->flags.byte;
    buf[4] = hdr->len;
    buf[5] = (hdr->len >> 8);

    uint16_t csum = msg_hdr_csum(buf);
    buf[6] = csum;
    buf[7] = (csum >> 8);
}

static inline int
msg_hdr_from_buf(const uint8_t buf[MSG_HDR_LEN], struct msg_hdr *hdr)
{
    uint16_t csum = msg_hdr_csum(buf);
    uint16_t hdr_csum = buf[6] | (buf[7] << 8);
    if (hdr_csum != csum) {
        return -1;
    }
    hdr->type = buf[0] | (buf[1] << 8);
    hdr->sid = buf[2];
    hdr->flags.byte = buf[3];
    hdr->len = buf[4] | (buf[5] << 8);
    hdr->csum = hdr_csum;
    return 0;
}

static inline void
print_msg_hdr(FILE *f, const struct msg_hdr *hdr)
{
    fprintf(f, "<msg type=%s sid=%d len=%d>", msg_type_to_str(hdr->type),
            hdr->sid, hdr->len);
}

enum msg_rx_state {
    MSG_RX_STATE_READING_HDR,
    MSG_RX_STATE_READING_BODY,
};

struct msg_rx {
    uint8_t hdr_buf[MSG_HDR_LEN];
    struct msg_hdr hdr;
    struct rbuf *body;
    int offset;
    enum msg_rx_state state : 8;
};

static inline void
msg_rx_init(struct msg_rx *rx)
{
    memset(rx, 0, sizeof(*rx));
}

static inline void
msg_rx_uninit(struct msg_rx *rx)
{
    if (rx->body != NULL) {
        rx->body = rbuf_unref(rx->body);
    }
}

enum msg_rx_rc {
    MSG_RX_RC_ERROR,
    MSG_RX_RC_BAD_HDR_CHKSUM,
    MSG_RX_RC_EOF,
    MSG_RX_RC_NEED_MORE,
    MSG_RX_RC_GOT_MSG,
};

/**
 * Reads 1 message from fd.  If this function returns zero,
 * use msg_decoder_last_hdr/body/unref_body to retrieve the message.
 * @return -1 on error, 1 on EOF, 0 otherwise.
 */
enum msg_rx_rc msg_rx_read1(struct msg_rx *rx, int fd);

static inline struct msg_hdr *
msg_rx_last_hdr(struct msg_rx *rx)
{
    return &rx->hdr;
}

static inline struct rbuf *
msg_rx_last_body(struct msg_rx *rx)
{
    return rx->body;
}

static inline void
msg_rx_unref_body(struct msg_rx *rx)
{
    rx->body = rbuf_unref(rx->body);
}

#endif /* MSG_H_ */
