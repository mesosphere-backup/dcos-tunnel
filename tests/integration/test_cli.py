import json
import os
import shlex
import signal
import subprocess
import sys
import time

from dcos import util
from dcos_tunnel import cli

from common import ssh_output

ssh_config_fmt = """\
Host {host}
    Port 22
"""

TEST_APP_NAME = "dcos-tunnel-cli-integration-app"
TEST_PORT_NAME = "test"
TEST_PORT_NUMBER = 80
TEST_PORT_PROTOCOL = "tcp"

TEST_SRV = "_{}._{}._{}.marathon.mesos".format(TEST_PORT_NAME,
                                               TEST_APP_NAME,
                                               TEST_PORT_PROTOCOL)
TEST_ADDR = "{}.marathon.mesos".format(TEST_APP_NAME)

TRANSPARENT_SUFFIX = ".mydcos.directory"

STANDARD_MODE = "standard"
TRANSPARENT_MODE = "transparent"


def setup_module():
    print("SETUP")

    app = {
        'id': "/{}".format(TEST_APP_NAME),
        'cpus': 0.1,
        'mem': 32,
        'instances': 1,
        'cmd': '/opt/mesosphere/bin/dcos-shell python '
               '/opt/mesosphere/active/dcos-integration-test/util/python_test_server.py $PORT0',
        'env': {
            'DCOS_TEST_UUID': TEST_APP_NAME,
            # required for python_test_server.py to run as nobody
            'HOME': '/'
        },
        'healthChecks': [
            {
                'protocol': 'MESOS_HTTP',
                'path': '/ping',
                'portIndex': 0,
                'gracePeriodSeconds': 5,
                'intervalSeconds': 10,
                'timeoutSeconds': 10,
                'maxConsecutiveFailures': 3
            }
        ],
        'portDefinitions': [{
            "protocol": TEST_PORT_PROTOCOL,
            "port": TEST_PORT_NUMBER,
            "name": TEST_PORT_NAME
        }],
        'acceptedResourceRoles': ["slave_public"],
        'requirePorts': True,
    }

    with util.temptext() as file_tup:
        f, fpath = file_tup
        app_bits = json.dumps(app).encode()
        os.write(f, app_bits)
        os.fsync(f)
        add_com = "dcos marathon app add {}".format(fpath)
        subprocess.call(shlex.split(add_com))

        time.sleep(5)
        for _ in range(360):
            ret = subprocess.call(shlex.split("dcos marathon deployment list"))
            if ret != 0:
                break
            time.sleep(1)


def teardown_module():
    print("TEARDOWN")
    subprocess.call(shlex.split("dcos marathon app remove {}".format(TEST_APP_NAME)))


def test_empty_config():
    local_port = "8800"
    config_file = "/tmp/dcos_tunnel_test_empty_config"
    targs = ["--port", local_port, "--config-file", config_file]
    url = "{}/ping".format(TEST_ADDR)
    cmd = "curl -sS -v --proxy http://127.0.0.1:8800 --fail {}".format(url)

    f = open(config_file, 'w+')
    f.write("")
    f.close()

    success, tret = _tunnel_runner("http", targs, cmd)
    assert success is True
    assert _tunnel_success(tret)


def test_simple_config():
    local_port = "8800"
    config_file = "/tmp/dcos_tunnel_test_empty_config"
    targs = ["--port", local_port, "--config-file", config_file]
    url = "{}/ping".format(TEST_ADDR)
    cmd = "curl -sS -v --proxy http://127.0.0.1:8800 --fail {}".format(url)
    host = cli.get_host("")

    f = open(config_file, 'w+')
    f.write(ssh_config_fmt.format(host=host))
    f.close()

    success, tret = _tunnel_runner("http", targs, cmd)
    assert success is True
    assert _tunnel_success(tret)


def test_socks_lookup():
    targs = ["--option StrictHostKeyChecking=no", "--option UserKnownHostsFile=/dev/null", "--port", "1080"]
    url = "{}/ping".format(TEST_ADDR)
    cmd = "curl -sS -v --proxy socks5h://127.0.0.1:1080 --fail {}".format(url)
    success, tret = _tunnel_runner("socks", targs, cmd)
    assert success is True
    assert _tunnel_success(tret)


def test_vpn_lookup():
    if sys.platform == 'win32':
        # VPN is currently unsupported on Windows
        return
    local_port = "1194"
    targs = ["--port", local_port]

    # XXX Hard-coded IP address of a DNS host from within a DC/OS cluster
    dns_host = '198.51.100.1'

    ip = '"$(dig @{} +short {})"'.format(dns_host, TEST_ADDR)
    url = "{}/ping".format(ip)
    cmd = "curl -sS -v --fail {}".format(url)

    success, tret = _tunnel_runner("vpn", targs, cmd)
    assert success is True
    assert _tunnel_success(tret)
    assert not _dangling_proc(['openvpn --config'])


def test_http_lookup():
    _http_lookup_helper(TEST_ADDR)


def test_http_srv_lookup():
    _http_lookup_helper(TEST_SRV)


def _http_lookup_helper(addr):
    local_port = "8800"
    targs = ["--port", local_port]
    url = "{}/ping".format(addr)
    cmd = "curl -sS -v --proxy http://127.0.0.1:8800 --fail {}".format(url)
    success, tret = _tunnel_runner("http", targs, cmd)
    assert success is True
    assert _tunnel_success(tret)


def test_http_transparent_lookup():
    _http_transparent_lookup_helper(TEST_ADDR + TRANSPARENT_SUFFIX)


def test_http_srv_transparent_lookup():
    srv = TEST_SRV + TRANSPARENT_SUFFIX

    # For some reason, on linux cURL is failing host resolution instead
    # of resolving *.mydcos.directory to localhost. So we manually do
    # a resolve before passing to cURL.
    curl_flags = '--resolve "{srv}:80:$(dig +short {srv})"'.format(srv=srv)

    _http_transparent_lookup_helper(srv, curl_flags=curl_flags)


def _http_transparent_lookup_helper(addr, curl_flags=""):
    local_port = "80"
    targs = ["--port", local_port]
    url = "{}/ping".format(addr)
    cmd = "curl -sS -v --fail {} {}".format(curl_flags, url)
    success, tret = _tunnel_runner("http", targs, cmd)
    assert success is True
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


def _tunnel_runner(ttype, tunnel_args, args, delay=30):
    tunnel = _tunnel(ttype, tunnel_args)
    success = False
    endtime = time.time() + delay
    while time.time() < endtime:
        stdout, stderr, ret = ssh_output(args)
        stdout_str = stdout.decode()
        stderr_str = stderr.decode()
        print("tunnel runner query stdout: {}".format(stdout_str))
        print("tunnel runner query stderr: {}".format(stderr_str))
        if ret == 0 and json.loads(stdout.decode()) == {"pong": True}:
            success = True
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

    return (success, tunnel.returncode)


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
