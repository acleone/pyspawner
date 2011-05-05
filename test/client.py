import hashlib
import socket
import struct
import sys
import time

import config
from msg import *

class Client(object):
    def __init__(self):
        self._s = None
        self._sid = 1
        self._last_sent_sid = None
        
    def connect(self, addr):
        self._s = socket.create_connection(addr)
        
    def auth(self, uname, pw):
        m = self._recv_msg(MSG_TYPE_AUTH_NONCE, NONCE_LEN)
        sha256 = hashlib.sha256()
        sha256.update(m.bodybytes)
        sha256.update(pw)
        digest = sha256.digest()
        self._send_msg(MSG_TYPE_AUTH_PW_REPLY, uname + '\x00' + digest)
        m = self._recv_msg(MSG_TYPE_SUCCESS, check_sid=True)
        print "--- Auth Successful"
        
    def start_session(self):
        self._send_msg(MSG_TYPE_START_SESSION)
        m = self._recv_msg(MSG_TYPE_SUCCESS, 4, check_sid=True)
        sessid = struct.unpack("<I", m.bodybytes)[0]
        print "--- Created Session id=%r" % (sessid,)
        
    def start_worker(self):
        self._send_msg(MSG_TYPE_START_WORKER)
        m = self._recv_msg(MSG_TYPE_SUCCESS, 4, check_sid=True)
        worker_pid = struct.unpack("<I", m.bodybytes)[0]
        print "--- Started Worker pid=%r" % (worker_pid,)
        
    def _recv_msg(self, check_type=None, check_len=None, check_sid=None):
        m = Msg.from_stream(self._s)
        print "> %r" % (m,)
        if check_type is not None:
            assert m.hdr.type == check_type
        if check_len is not None:
            assert m.hdr.len == check_len
        if check_sid is not None:
            assert m.hdr.sid == self._last_sent_sid
        return m
    
    def _send_msg(self, type, bodybytes=''):
        m_reply = Msg(MsgHdr(type=type, sid=self._sid), bodybytes)
        print "< %r" % (m_reply,)
        self._s.send(m_reply.encode())
        self._last_sent_sid = self._sid
        self._sid += 1
        return m_reply

def main():
    c = Client()
    c.connect(config.ADDR)
    c.auth(config.UNAME, config.PW)
#    time.sleep(10)
    c.start_session()
#    time.sleep(10)
    c.start_worker()
    while 1:
        c._recv_msg()

if __name__ == '__main__':
    main()
