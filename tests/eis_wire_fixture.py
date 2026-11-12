"""One native libeis peer and its actual portal-issued EIS descriptor."""
import array
import contextlib
import json
import os
import socket
import subprocess

@contextlib.contextmanager
def wire_peer(test,provider,records_type,config,properties=None,expected_exit=0):
    own,exported=socket.socketpair()
    server=None;records=None;received=[]
    try:
        server=subprocess.Popen([provider,'--control-fd',str(exported.fileno())],pass_fds=(exported.fileno(),),
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        exported.close();records=records_type(server)
        server.stdin.write(json.dumps(config)+'\n');server.stdin.flush();own.settimeout(5)
        data,messages,flags,_=own.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
        test.assertEqual(data,b'E');test.assertFalse(flags&socket.MSG_CTRUNC)
        for level,kind,content in messages:
            test.assertEqual((level,kind),(socket.SOL_SOCKET,socket.SCM_RIGHTS))
            values=array.array('i');values.frombytes(content);received.extend(values)
        test.assertEqual(len(received),1)
        os.set_inheritable(received[0],False)
        with test.mutex:
            type(test).mode='eis-wire';type(test).wire_fd=received.pop();type(test).wire_properties=properties or {}
        records.wait(lambda row:row.get('serverReady'))
        yield records
        if expected_exit==0:records.command('quit')
        test.assertEqual(server.wait(timeout=5),expected_exit,server.stderr.read())
    finally:
        own.close();exported.close()
        for fd in received:os.close(fd)
        with test.mutex:
            if test.wire_fd>=0:os.close(test.wire_fd);type(test).wire_fd=-1
        if server:
            if server.poll() is None:server.kill();server.wait(timeout=5)
            for stream in (server.stdin,server.stderr):stream.close()
            if records:
                records.thread.join(timeout=5);test.assertFalse(records.thread.is_alive(),'Owned EIS reader survived cleanup')
            server.stdout.close()
