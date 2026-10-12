#!/usr/bin/env python3
"""Linux interactive/terminal-close integration using a real local carrier."""
import os
import pathlib
import pty
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())

def wait_child(pid, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        child, status = os.waitpid(pid, os.WNOHANG)
        if child:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.05)
    raise AssertionError('managed launcher did not exit')

def descendants(pid):
    found = []
    for entry in pathlib.Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
            if int(fields[1]) == pid:
                found.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return found

with tempfile.TemporaryDirectory(prefix='openflux-pty-') as temp:
    root = pathlib.Path(temp)
    key = root / 'key'
    key.write_text(secrets.token_hex(32))
    os.chmod(key, 0o600)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        address = f'127.0.0.1:{listener.getsockname()[1]}'
    config = root / 'client.conf'
    config.write_text(f'[Interface]\nRole = client\nEncryptionKeyFile = key\nForwardSecrecy = true\n[Transport "direct"]\nDial = {address}\n')
    exit_node = subprocess.Popen([binary, '--role=exit', '--mode=l4', '--negotiate', '--forward-secrecy', '--transport=direct', '--direct-listen='+address, '--encryption-key-file='+str(key)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for close_terminal in (False, True):
            pid, fd = pty.fork()
            if pid == 0:
                os.execv(binary, [binary, 'run', '--config='+str(config), '--timeout=15s', '--', '/bin/sh', '-c', 'printf "READY\\n"; read value; printf "RECEIVED:%s\\n" "$value"'])
            data = b''
            deadline = time.monotonic() + 18
            try:
                while b'READY' not in data and time.monotonic() < deadline:
                    readable, _, _ = select.select([fd], [], [], 0.2)
                    if readable:
                        data += os.read(fd, 4096)
                assert b'READY' in data, 'interactive application not ready'
                owned = descendants(pid)
                assert len(owned) >= 2, 'core/application ownership missing'
                if close_terminal:
                    os.close(fd)
                    fd = None
                    wait_child(pid)
                else:
                    os.write(fd, b'hello\n')
                    while b'RECEIVED:hello' not in data and time.monotonic() < deadline:
                        readable, _, _ = select.select([fd], [], [], 0.2)
                        if readable:
                            data += os.read(fd, 4096)
                    assert b'RECEIVED:hello' in data, 'foreground terminal input was lost'
                    assert wait_child(pid) == 0, 'application exit code changed'
                for child in owned:
                    stat = pathlib.Path(f'/proc/{child}/stat')
                    if stat.exists():
                        assert stat.read_text().rsplit(') ', 1)[1].split()[0] == 'Z', 'owned process survived launcher exit'
                print('Terminal close cleanup: OK' if close_terminal else 'Interactive input and normal exit: OK')
            finally:
                if fd is not None:
                    os.close(fd)
    finally:
        exit_node.terminate()
        try:
            exit_node.wait(timeout=3)
        except subprocess.TimeoutExpired:
            exit_node.kill()
            exit_node.wait()
