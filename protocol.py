"""Bounded Unix socket requests with optional stdio file descriptor passing."""
import array
import json
import os
import socket
import struct

LIMIT = 256 * 1024


def send(connection, value, fds=()):
    payload = json.dumps(value).encode()
    if len(payload) > LIMIT:
        raise ValueError('control socket message exceeds 256 KiB')
    payload = struct.pack('!I', len(payload)) + payload
    if fds:
        descriptors = array.array('i', fds)
        written = connection.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)])
        if written < len(payload):
            connection.sendall(payload[written:])
    else:
        connection.sendall(payload)


def receive(connection):
    fds = []
    try:
        def exact(length):
            data = bytearray()
            while len(data) < length:
                block, controls, flags, _ = connection.recvmsg(min(65536, length - len(data)), socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
                for level, kind, content in controls:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array('i')
                        values.frombytes(content[:len(content) - len(content) % values.itemsize])
                        fds.extend(values)
                if flags & socket.MSG_CTRUNC or len(fds) > 3:
                    raise ValueError('control socket: unexpected descriptor count')
                if not block:
                    raise EOFError('control socket disconnected')
                data.extend(block)
            return data
        length = struct.unpack('!I', exact(4))[0]
        if not 0 < length <= LIMIT:
            raise ValueError('control socket message exceeds 256 KiB')
        return json.loads(exact(length)), fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise
