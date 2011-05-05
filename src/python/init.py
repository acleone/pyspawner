import json
import os

_globals = {}

def recv_msgs():
    buf = []
    while 1:
        s = os.read(3, 4096)
        if not s:
            raise EOFError()
        while s:
            i = s.find('\x00')
            if i == -1:
                buf.append(s)
                break
            buf.append(s[:i])
            full_msg = ''.join(buf)
            if full_msg:
                yield json.loads(full_msg)
            buf = []
            s = s[i + 1:]
            
def send_msg(m):
    out = json.dumps(m) + '\x00'
    while out:
        nbytes = os.write(4, out)
        out = out[nbytes:]



def main():
    exec '''
import sys
import time
''' in _globals
    

def run():
    """
    Run after a fork.
    """
    for msg in recv_msgs():
        if msg['t'] == 'shutdown':
            return
        if msg['t'] == 'exec':
            exec msg['code'] in _globals
            send_msg({'t': 'done'})
            
        
if __name__ == '__main__':
    """
    Run when pyspawner is first started.
    """
    main()
