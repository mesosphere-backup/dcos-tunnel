import os
import shlex
import signal
import subprocess
import sys
import time

from common import ssh_output


def test_empty_config():
    local_port = "8800"
    config_file = "/tmp/dcos_tunnel_test_empty_config"
    targs = ["--port", local_port, "--config-file", config_file]
    args = ("curl -sS -v --proxy http://127.0.0.1:8800 " +
            "--fail marathon.mesos.mydcos.directory")

    f = open(config_file, 'w+')
    f.write("")
    f.close()

    _, _, ret, tret = _tunnel_runner("http", targs, args)
    assert ret == 0
    assert _tunnel_success(tret)


def test_socks_lookup():
    targs = ["--option StrictHostKeyChecking=no", "--port", "1080"]
    args = ("curl -sS -v --proxy socks5h://127.0.0.1:1080 " +
            "--fail marathon.mesos.mydcos.directory")
    _, _, ret, tret = _tunnel_runner("socks", targs, args)
    assert ret == 0
    assert _tunnel_success(tret)


def test_vpn_lookup():
    if sys.platform == 'win32':
        # VPN is currently unsupported on Windows
        return
    local_port = "1194"
    targs = ["--port", local_port]

    # XXX Hard-coded IP address of a DNS host from within a DC/OS cluster
    dns_host = '198.51.100.1'
    args = ("ping -c1 $(host -t A master.mesos {} | ".format(dns_host) +
            "tail -n1 | rev | cut -f1 -d' ' | rev)")

    _, _, ret, tret = _tunnel_runner("vpn", targs, args)
    assert ret == 0
    assert _tunnel_success(tret)
    assert not _dangling_proc(['openvpn --config'])


def test_http_lookup():
    local_port = "8800"
    targs = ["--port", local_port]
    args = ("curl -sS -v --proxy http://127.0.0.1:8800 " +
            "--fail marathon.mesos.mydcos.directory")
    _, _, ret, tret = _tunnel_runner("http", targs, args)
    assert ret == 0
    assert _tunnel_success(tret)


def test_http_transparent_lookup():
    local_port = "80"
    targs = ["--port", local_port]
    args = "curl -sS -v --fail marathon.mesos.mydcos.directory"
    _, _, ret, tret = _tunnel_runner("http", targs, args)
    assert ret == 0
    assert _tunnel_success(tret)


def _is_privileged():
    return os.geteuid() == 0


def _dangling_proc(procstrlist):
    stdout, _, _ = ssh_output(['ps', 'aux'])
    for line in stdout.splitlines():
        line = line.decode()
        for pstr in procstrlist:
            if pstr in line:
                return True
    return False


def _tunnel_runner(ttype, tunnel_args, args, delay=15):
    tunnel = _tunnel(ttype, tunnel_args)
    endtime = time.time() + delay
    while time.time() < endtime:
        stdout, stderr, ret = ssh_output(args)
        if ret == 0:
            break

    if sys.platform == 'win32':
        os.kill(tunnel.pid, signal.CTRL_BREAK_EVENT)
    else:
        try:
            os.killpg(os.getpgid(tunnel.pid), signal.SIGTERM)
        except OSError:
            print("ERROR: Process did not exist")

    tout, terr = tunnel.communicate()
    print('Runner STDOUT: {}'.format(tout.decode()))
    print('Runner STDERR: {}'.format(terr.decode()))

    return (stdout, stderr, ret, tunnel.returncode)


def _tunnel_success(tunnel_returncode):
    """
    The behavior we want from the tunnel is that it doesn't exit, and has
    to be killed. Popen will return a negative exit code if the process is
    killed, so that is what we want.
    """
    return tunnel_returncode < 0


def _tunnel(ttype, args):
    cli_test_ssh_key_path = os.environ['CLI_TEST_SSH_KEY_PATH']

    cmd = ('ssh-agent /bin/bash -c "ssh-add {0} 2> /dev/null && ' +
           '$(which dcos-tunnel) tunnel {1} {2}"'
           ).format(cli_test_ssh_key_path, ttype, ' '.join(args))

    pfn = None
    if sys.platform != 'win32':
        pfn = os.setsid

    cflag = 0
    if sys.platform == 'win32':
        cflag = subprocess.CREATE_NEW_PROCESS_GROUP

    print(cmd)
    return subprocess.Popen(shlex.split(cmd), preexec_fn=pfn,
                            creationflags=cflag, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
