import re
import struct

MSG_HDR_LEN = 8
NONCE_LEN = 32
SHA256_DIGEST_LEN = 256

def msg_hdr_csum(buf):
    r = sum([ord(c) for c in buf[0:6]])
    return (~r) & 0xffff

class MsgHdr(object):
    
    def __init__(self, type=0, sid=0, f_more=False, len=0, csum=0):
        self.type = type
        self.sid = sid
        self.f_more = f_more
        self.len = len
        self.csum = csum
        
    def encode(self, body_len):
        flags_byte = (self.f_more << 7)
        buf = struct.pack("<HBBH", self.type, self.sid, flags_byte, body_len)
        csum_bytes = struct.pack("<H", msg_hdr_csum(buf))
        return buf + csum_bytes
    
    @classmethod
    def decode(cls, buf):
        hdr = cls()
        csum = msg_hdr_csum(buf)
        (hdr.type, hdr.sid, flags_byte, hdr.len,
         hdr_csum) = struct.unpack("<HBBHH", buf[:MSG_HDR_LEN])
        if csum != hdr_csum:
           raise ValueError("bad hdr checksum")
        hdr.f_more = bool(flags_byte & 0x80)
        return hdr
        
    def __repr__(self):
        typestr = str(self.type)
        if self.type < len(ENUM_CONSTS):
            typestr = ENUM_CONSTS[self.type]
        return "%s(type=%s, sid=%d, f_more=%d, len=%d)" % (
                   self.__class__.__name__, typestr, self.sid, self.f_more,
                   self.len)


class Msg(object):
    def __init__(self, hdr=None, bodybytes=None):
        self.hdr = hdr
        self.bodybytes = bodybytes
        
    def encode(self):
        if self.bodybytes is None:
            self.bodybytes = b''
        return self.hdr.encode(len(self.bodybytes)) + self.bodybytes
    
    @classmethod
    def from_stream(cls, s):
        readf = s.read if hasattr(s, 'read') else s.recv
        data = None
        hdrbytes = b''
        bodybytes = b''
        while len(hdrbytes) < MSG_HDR_LEN:
            data = readf(MSG_HDR_LEN - len(hdrbytes))
            if not data:
                # EOF
                raise ValueError('EOF')
            hdrbytes += data
        hdr = MsgHdr.decode(hdrbytes)
        while len(bodybytes) < hdr.len:
            data = readf(hdr.len - len(bodybytes))
            if not data:
                # EOF
                raise ValueError('EOF')
            bodybytes += data
        return Msg(hdr, bodybytes)
    
    def __repr__(self):
        return "%s(%r, %r)" % (self.__class__.__name__, self.hdr,
                               self.bodybytes)
              
ENUM_CONSTS = re.findall('MSG_TYPE_[^,]+', '''
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
''')

def build_consts():
    import msg
    for i, s in enumerate(ENUM_CONSTS):
        msg.__dict__[s] = i
build_consts()