"""
Description:
    SOCKS proxy, HTTP proxy, and VPN access to a DC/OS cluster.

Usage:
    dcos tunnel --info
    dcos tunnel socks [--port=<local-port>]
                      [--config-file=<path>]
                      [--user=<user>]
                      [--privileged]
                      [--option SSHOPT=VAL ...]
    dcos tunnel http [--port=<local-port>]
                     [--config-file=<path>]
                     [--user=<user>]
                     [--privileged]
                     [--verbose]
    dcos tunnel vpn [--port=<local-port>]
                    [--config-file=<path>]
                    [--user=<user>]
                    [--privileged]
                    [--container=<container>]
                    [--client=<path>]

Commands:
    socks
        Establish a SOCKS proxy over SSH to the master node of your DCOS
        cluster.
    http
        Establish a HTTP proxy over SSH to the master node of your DCOS
        cluster.
    vpn
        Establish a VPN over SSH to the master node of your DCOS cluster.

Options:
    --help
        Show this screen.
    --version
        Print version information.
    --config-file=<path>
        Path to SSH configuration file.
    --info
        Show a short description of this subcommand.
    --option SSHOPT=VAL
        The SSH options. For information, enter `man ssh_config` in your
        terminal.
    --user=<user>
        The SSH user, where the default user [default: core].
    --verbose
        Verbose output
    --port=<local-port>
        The port to listen on locally
        Defaults to SOCKS:1080, HTTP:80, VPN:1194
    --container=<container>
        The OpenVPN container to run
        [default: dcos/dcos-cli-vpn:1-1d6e59e4109beb78340304c0a24c7c0ced49c6c6]
    --client=<path>
        The OpenVPN client to run [default: openvpn]
    --privileged
        Assume the user is of 'superuser' or 'Administrator" equivalent
"""

import binascii
import distutils.spawn
import os
import random
import select
import shlex
import shutil
import signal
import socketserver
import string
import subprocess
import sys
import threading

import docopt

from dcos import cmds, emitting, mesos, util
from dcos.errors import DCOSException, DefaultError
from dcos_tunnel import constants

import paramiko

logger = util.get_logger(__name__)
emitter = emitting.FlatEmitter()

# Always use get_pty=True with SSHClient.exec_command()! Otherwise the remote
# process won't terminate.

# If there isn't a left hand side to SSHClient.exec_command(), then it will
# be garbage collected

# XXX Paramiko suggests that you client.close() ALWAYS, probably gonna
#   have to do this in the signal handler as well...

# XXX Currently using daemonic threads but it seems that they're generally
#   frowned upon.


def signal_handler(signal, frame):
    emitter.publish(DefaultError(" User interrupted command. Exiting..."))
    sys.exit(130)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = docopt.docopt(
        __doc__,
        version=constants.version)

    try:
        ret = cmds.execute(_cmds(), args)
    except DCOSException as e:
        emitter.publish(e)
        ret = 1
    return ret


def _cmds():
    """
    :returns: All of the supported commands
    :rtype: [Command]
    """

    return [
        cmds.Command(
            hierarchy=['tunnel', '--info'],
            arg_keys=[],
            function=_info),

        cmds.Command(
            hierarchy=['tunnel', 'socks'],
            arg_keys=['--port', '--config-file', '--user', '--privileged',
                      '--option'],
            function=_socks),

        cmds.Command(
            hierarchy=['tunnel', 'http'],
            arg_keys=['--port', '--config-file', '--user', '--privileged',
                      '--verbose'],
            function=_http),

        cmds.Command(
            hierarchy=['tunnel', 'vpn'],
            arg_keys=['--port', '--config-file', '--user', '--privileged',
                      '--container', '--client'],
            function=_vpn),
    ]


def _info():
    """
    Print tunnel cli information.

    :returns: process return code
    :rtype: int
    """

    # This is what prints out in the default command page, it should be
    # as short as possible.
    emitter.publish("Proxy and VPN access to DC/OS cluster")
    return 0


def ssh_exec_wait(output):
    _, stdout, _ = output
    stdout.channel.recv_exit_status()


def forward_tunnel(local_port, remote_host, remote_port, transport):
    """
    A blocking command
    """
    # This little dance allows configuration of the Handler object.
    # (socketserver doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander (Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
    try:
        ForwardServer(('', local_port), SubHander).serve_forever()
    except PermissionError as e:
        msg = "*** Permission denied during port forwarding: {}"
        logger.error(msg.format(repr(e)))
    except OSError as e:
        msg = "*** Error during port forwarding: {}"
        logger.error(msg.format(repr(e)))


class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            daddr = (self.chain_host, self.chain_port)
            saddr = self.request.getpeername()
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   dest_addr=daddr,
                                                   src_addr=saddr)
        except Exception as e:
            msg = 'Incoming request to {}:{} failed: {}'
            logger.debug(msg.format(self.chain_host, self.chain_port, repr(e)))
            return
        if chan is None:
            msg = 'Incoming request to {}:{} was rejected by the SSH server.'
            logger.debug(msg.format(self.chain_host, self.chain_port))
            return

        msg = 'Connected! Tunnel open {} -> {} -> {}'
        fmsg = msg.format(self.request.getpeername(),
                          chan.getpeername(),
                          (self.chain_host, self.chain_port))
        logger.debug(fmsg)
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        logger.debug('Tunnel closed from {}'.format(peername))


class CustomWarningPolicy(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        msg = '*** Unknown {} host key for {}: {}'
        msg = msg.format(key.get_name(),
                         hostname,
                         binascii.hexlify(key.get_fingerprint()).decode())
        logger.warning(msg)


def sshclient(config_file, user):

    # XXX Should probably also deal with keepalives if the user has
    #   it in their config
    # XXX Look at other config options that may need to be translated to
    #   paramiko

    if not os.environ.get('SSH_AUTH_SOCK'):
        msg = ("*** If you are using `sudo`, you may need to pass the "
               "SSH_AUTH_SOCK variable explicity: "
               "`sudo SSH_AUTH_SOCK=$SSH_AUTH_SOCK dcos tunnel ...` "
               "\n\n"
               "*** There is no SSH_AUTH_SOCK env variable, which likely "
               "means you aren't running `ssh-agent`. Please "
               "run `ssh-agent`, then add your private key with `ssh-add`.")
        raise DCOSException(msg)

    port = 22
    dcos_client = mesos.DCOSClient()
    host = dcos_client.metadata().get('PUBLIC_IPV4')
    if not host:
        host = mesos.MesosDNSClient().hosts('leader.mesos.')[0]['ip']

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(CustomWarningPolicy())

    config = parse_config(config_file, host)
    if config is not None and config['port']:
        port = config['port']

    try:
        client.connect(host, port=port, username=user)
    except Exception as e:
        msg = '*** Failed to connect to {}:{}: {}'
        raise DCOSException(msg.format(host, port, e))

    return client


def parse_config(config_file, host):
    if config_file is None:
        return None
    config_file = os.path.expanduser(config_file)
    if not os.path.isfile(config_file):
        return None

    config = paramiko.config.SSHConfig
    f = open(config_file, 'r')
    config.parse(f)
    f.close()
    return config.lookup(host)


def validate_port(port, default=None):
    """
    Return a port, or None if invalid.
    """
    if port is None and (default is not None):
        port = default

    try:
        port = int(port)
    except ValueError:
        logger.error("*** '{}' is not a valid port.".format(port))
        return None

    if port > 65535 or port < 0:
        logger.error("*** port {} out of range.".format(port))
        return None

    if port < 1024 and (not is_privileged()):
        msg = ("*** You don't have permission to bind to port {}. " +
               "You can choose a different one with `--port`." +
               "\n{}".format(constants.unprivileged_suggestion))
        logger.error(msg.format(port))
        return None

    return port


def _socks(port, config_file, user, privileged, option):
    """
    SOCKS proxy into a DC/OS node using the IP addresses found in master's
    state.json

    :param port: The port the SOCKS proxy listens on locally
    :type port: int | None
    :param option: SSH option
    :type option: [str]
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param privileged: If True, override privilege checks
    :type privileged: bool
    :returns: process return code
    :rtype: int
    """

    if privileged:
        os.environ[constants.privileged] = '1'
    port = validate_port(port, default=1080)
    if port is None:
        return 1

    ssh_options = util.get_ssh_options(config_file, option)
    dcos_client = mesos.DCOSClient()
    host = dcos_client.metadata().get('PUBLIC_IPV4')
    if not host:
        host = mesos.MesosDNSClient().hosts('leader.mesos.')[0]['ip']

    scom = "ssh -N -D {} {} {}@{}".format(port, ssh_options, user, host)

    emitter.publish('SOCKS proxy listening on port {}'.format(port))
    return subprocess.call(shlex.split(scom))


def logging_exec(ssh_client, ssh_command, outputlog, raw=False):
    """
    raw: If True, treat outputlog as a file descriptor
    """
    # This doesn't use paramiko.SSHClient.exec_command() because that doesn't
    # expose the option to combine stderr and stdout
    chan = ssh_client.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(ssh_command)
    chan.set_combine_stderr(True)
    stdout = chan.makefile('r', -1)

    # It's not using `for line in stdout.readlines()` because it's broken
    # in paramiko. It blocks until EOF is reached to output anything.
    line = stdout.readline()
    while line != "":
        if raw:
            os.write(outputlog, line.encode(sys.getdefaultencoding()))
            os.fsync(outputlog)
        else:
            outputlog.write(line)
            outputlog.flush()
        line = stdout.readline()


def _http(port, config_file, user, privileged, verbose):
    """
    Proxy HTTP traffic into a DC/OS cluster using the IP addresses found in
    master's state.json

    :param port: The port the HTTP proxy listens on locally
    :type port: int | None
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param privileged: If True, override privilege checks
    :type privileged: bool
    :param verbose: Verbose output
    :type verbose: bool
    :returns: process return code
    :rtype: int
    """

    if privileged:
        os.environ[constants.privileged] = '1'
    port = validate_port(port, default=80)
    if port is None:
        return 1
    client = sshclient(config_file, user)

    http_proxy = '/opt/mesosphere/bin/octarine'
    proxy_id = rand_str(16)

    scom = http_proxy
    if verbose:
        scom += ' --verbose'
    scom += " {}".format(proxy_id)

    http_proxy_server = threading.Thread(target=logging_exec,
                                         args=(client, scom, sys.stderr),
                                         daemon=True)
    http_proxy_server.start()

    scom = "{} --client --port {}".format(http_proxy, proxy_id)
    _, query_stdout, _ = client.exec_command(scom, get_pty=True)
    remote_port = int(query_stdout.read().decode().strip())

    msg = 'HTTP proxy listening locally on port {}, remotely on port {}'
    emitter.publish(msg.format(port, remote_port))
    forward_tunnel(port, '127.0.0.1', remote_port, client.get_transport())

    client.close()
    return 0


def is_privileged():
    return (os.geteuid() == 0) or (os.environ.get(constants.privileged) == '1')


def rand_str(n):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.SystemRandom().choice(choices) for _ in range(n))


def gen_hosts(ssh_client):
    dcos_client = mesos.DCOSClient()
    mesos_hosts = []
    dns_hosts = []

    for host in mesos.MesosDNSClient().hosts('master.mesos.'):
        mesos_hosts.append(host['ip'])

    summary = dcos_client.get_state_summary()
    for host in summary['slaves']:
        mesos_hosts.append(host['hostname'])

    scom = 'cat /etc/resolv.conf'
    _, query_stdout, _ = ssh_client.exec_command(scom, get_pty=True)
    for line in query_stdout.readlines():
        if line.startswith('nameserver'):
            host = line.strip().split()[1]
            dns_hosts.append(host)

    return (mesos_hosts, dns_hosts)


def container_cp(ssh_client, container_name, remote_filepath, local_file):
    scom = 'docker exec {} bash -c "cat {}"'
    scom = scom.format(container_name, remote_filepath)
    _, query_stdout, _ = ssh_client.exec_command(scom, get_pty=True)
    os.write(local_file, query_stdout.read())
    os.fsync(local_file)


def run_vpn(command, output_file):
    return subprocess.call(shlex.split(command),
                           stdout=output_file,
                           stderr=output_file)


def _vpn(port, config_file, user, privileged, openvpn_container, vpn_client):
    """
    VPN into a DC/OS cluster using the IP addresses found in master's
    state.json

    :param port: The port the HTTP proxy listens on locally
    :type port: int | None
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param privileged: If True, override privilege checks
    :type privileged: bool
    :param openvpn_container: `docker pull <param>` should work
    :type openvpn_container: str
    :param vpn_client: Relative or absolute path to openvpn client
    :type vpn_client: str
    :returns: process return code
    :rtype: int
    """

    if privileged:
        os.environ[constants.privileged] = '1'

    if sys.platform == 'win32':
        logger.error("*** VPN is currently unsupported on Windows")
        return 1

    if not is_privileged():
        logger.error("*** You don't have permission to run this command." +
                     "\n{}".format(constants.unprivileged_suggestion))
        return 1

    if not ((os.path.isfile(vpn_client) and os.access(vpn_client, os.X_OK)) or
            shutil.which(vpn_client)):
        msg = "*** Not a valid executable: {}"
        logger.error(msg.format(vpn_client))
        return 1

    port = validate_port(port, default=1194)
    if port is None:
        return 1
    client = sshclient(config_file, user)

    if not distutils.spawn.find_executable(vpn_client):
        msg = ("You don't seem to have the '{}' executable. Please add it to "
               "your $PATH or equivalent.")
        logger.error(msg.format(vpn_client))
        return 1

    mesos_hosts, dns_hosts = gen_hosts(client)
    container_name = "openvpn-{}".format(rand_str(8))
    remote_openvpn_dir = "/etc/openvpn"
    remote_keyfile = "{}/static.key".format(remote_openvpn_dir)
    remote_clientfile = "{}/client.ovpn".format(remote_openvpn_dir)

    emitter.publish("\nATTENTION: IF DNS DOESN'T WORK, add these DNS servers!")
    for host in dns_hosts:
        emitter.publish(host)

    parsed_routes = ','.join(mesos_hosts)
    parsed_dns = ','.join(dns_hosts)

    with util.temptext() as server_tup, \
            util.temptext() as key_tup, \
            util.temptext() as config_tup, \
            util.temptext() as client_tup:

        serverfile, serverpath = server_tup
        keyfile, keypath = key_tup
        clientconfigfile, clientconfigpath = config_tup
        clientfile, clientpath = client_tup

        scom = """\
               docker run --rm --cap-add=NET_ADMIN -p 0:1194 \
               -e "OPENVPN_ROUTES={}" -e "OPENVPN_DNS={}" --name {} {}\
               """.format(parsed_routes, parsed_dns, container_name,
                          openvpn_container)

        # FDs created when python opens a file have O_CLOEXEC set, which
        # makes them invalid in new threads (cloning). So we duplicate the
        # FD, which creates one without O_CLOEXEC.
        serverfile_dup = os.dup(serverfile)
        # XXX This FD is never closed because it would cause the vpn server
        #   thread to crash

        vpn_server = threading.Thread(target=logging_exec,
                                      args=(client, scom, serverfile_dup,
                                            True),
                                      daemon=True)
        vpn_server.start()

        msg = "\nWaiting for VPN server in container '{}' to come up..."
        emitter.publish(msg.format(container_name))
        scom = ("until "
                """[ "$(docker inspect --format='{{ .State.Running }}' """
                """%s 2>/dev/null)" = "true" ] 2>/dev/null; do sleep 0.5; """
                """done""") % (container_name)
        scom += (";"
                 """docker exec {} "sh -c 'until [ -s {} ]; do sleep 0.5; """
                 """done'" """).format(container_name, remote_keyfile)
        scom += (";"
                 """docker exec {} "sh -c 'until [ -s {} ]; do sleep 0.5; """
                 """done'" """).format(container_name, remote_clientfile)
        server_setup = client.exec_command(scom, get_pty=True)
        ssh_exec_wait(server_setup)

        scom = ("""docker inspect --format='"""
                """{{range $p, $conf := .NetworkSettings.Ports}}"""
                """{{(index $conf 0).HostPort}}{{end}}' %s"""
                ) % (container_name)
        _, query_stdout, _ = client.exec_command(scom, get_pty=True)
        remote_port = int(query_stdout.read().decode().strip())

        def tunnel_def():
            ssh_transport = client.get_transport()
            forward_tunnel(port, '127.0.0.1', remote_port, ssh_transport)
        tunnel = threading.Thread(target=tunnel_def, daemon=True)
        tunnel.start()

        container_cp(client, container_name, remote_keyfile, keyfile)
        container_cp(client, container_name, remote_clientfile,
                     clientconfigfile)

        vpn_com = ('{} --config {} --secret {} --port {}')
        vpn_com = vpn_com.format(vpn_client, clientconfigpath, keypath, port)

        emitter.publish("\nVPN server output at {}".format(serverpath))
        emitter.publish("VPN client output at {}\n".format(clientpath))
        ret = run_vpn(vpn_com, clientfile)

        client.close()
        input('Exited. Temporary files will be gone once you hit <Return>.')
        return ret


if __name__ == "__main__":
    main()
