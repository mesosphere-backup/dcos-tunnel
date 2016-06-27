import os
import shlex
import signal
import subprocess
import sys
import time

from common import ssh_output


def test_node_socks_lookup():
    targs = ["--master-proxy", "--port", "1080"]
    args = ("curl --proxy socks5h://127.0.0.1:1080 " +
            "--fail marathon.mesos.mydcos.directory")
    _, _, ret = _node_tunnel_runner("socks-proxy", targs, args)
    assert ret == 0


def test_node_vpn_lookup():
    if sys.platform == 'win32':
        # VPN is currently unsupported on Windows
        return
    local_port = "1194"
    targs = ["--master-proxy", "--port", local_port]

    # XXX This is the hard-coded IP address of a DNS host
    # I'd like to `curl marathon.mesos` but it seems like the option to set
    # the DNS server through OpenVPN doesn't work
    args = "ping -c1 198.51.100.1"

    _, _, ret = _node_tunnel_runner("vpn", targs, args, delay=20)
    assert ret == 0
    assert not _dangling_proc(['OPENVPN_ROUTES=',
                               '-N -L {0}:127.0.0.1:'.format(local_port),
                               'openvpn --config'])


def test_node_http_lookup():
    local_port = "8800"
    targs = ["--master-proxy", "--port", local_port]
    args = ("curl --proxy http://127.0.0.1:8800 " +
            "--fail marathon.mesos.mydcos.directory")
    _, _, ret = _node_tunnel_runner("http-proxy", targs, args)
    assert ret == 0
    assert not _dangling_proc(['/opt/mesosphere/bin/octarine',
                               '-N -L {0}:127.0.0.1:'.format(local_port)])


def test_node_http_transparent_lookup():
    local_port = "80"
    targs = ["--master-proxy", "--port", local_port]
    args = "curl --fail marathon.mesos.mydcos.directory"
    _, _, ret = _node_tunnel_runner("http-proxy", targs, args, sudo=True)
    assert ret == 0
    assert not _dangling_proc(['/opt/mesosphere/bin/octarine',
                               '-N -L {0}:127.0.0.1:'.format(local_port)])


def _dangling_proc(procstrlist):
    stdout, _, _ = ssh_output(['ps', 'aux'])
    for line in stdout.splitlines():
        for pstr in procstrlist:
            if pstr in line:
                return True
    return False


def _node_tunnel_runner(ttype, tunnel_args, args, delay=5, sudo=False):
    tunnel = _node_tunnel(ttype, tunnel_args, sudo=sudo)
    time.sleep(delay)
    stdout, stderr, ret = ssh_output(args)

    if sys.platform == 'win32':
        os.kill(tunnel.pid, signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(os.getpgid(tunnel.pid), signal.SIGTERM)

    return (stdout, stderr, ret)


def _node_tunnel(ttype, args, sudo=False):
    if os.environ.get('CLI_TEST_MASTER_PROXY') and \
            '--master-proxy' not in args:
        args.append('--master-proxy')

    cli_test_ssh_key_path = os.environ['CLI_TEST_SSH_KEY_PATH']

    sudo_comm = ''
    if sudo:
        sudo_comm = 'sudo -n'
    cmd = ('ssh-agent /bin/bash -c "ssh-add {0} 2> /dev/null && ' +
           '{1} dcos node {2} --option StrictHostKeyChecking=no ' +
           '{3}"').format(cli_test_ssh_key_path, sudo_comm, ttype,
                          ' '.join(args))

    pfn = None
    if sys.platform != 'win32':
        pfn = os.setsid

    cflag = 0
    if sys.platform == 'win32':
        cflag = subprocess.CREATE_NEW_PROCESS_GROUP

    return subprocess.Popen(shlex.split(cmd), preexec_fn=pfn,
                            creationflags=cflag)
