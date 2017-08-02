"""
Description:
    SOCKS proxy, HTTP proxy, and VPN access to a DC/OS cluster.

Usage:
    dcos tunnel --info
                [--help]
                [--version]
    dcos tunnel socks [--port=<local-port>]
                      [--config-file=<path>]
                      [--user=<user>]
                      [--privileged]
                      [--sport=<ssh_port>]
                      [--host=<host>]
                      [--verbose]
                      [--option SSHOPT=VAL ...]
    dcos tunnel http [--port=<local-port>]
                     [--config-file=<path>]
                     [--user=<user>]
                     [--privileged]
                     [--sport=<ssh_port>]
                     [--host=<host>]
                     [--verbose]
    dcos tunnel vpn [--port=<local-port>]
                    [--config-file=<path>]
                    [--user=<user>]
                    [--privileged]
                    [--sport=<ssh_port>]
                    [--host=<host>]
                    [--verbose]
                    [--container=<container>]
                    [--client=<path>]
                    [--remote-docker=<docker-command>]
                    [--addroute <ip-address> ...]
                    [--delroute <ip-address> ...]

Commands:
    socks
        Establish a SOCKS proxy over SSH to the master node of your DC/OS
        cluster.

    http
        Establish a HTTP proxy over SSH to the master node of your DC/OS
        cluster.

        When bound to port 80, the HTTP proxy operates in "transparent" mode
        where applications do not need to be configured to use the proxy, but
        additionally requires appending `.mydcos.directory` to the domain
        (e.g. http://example.com:8080/?query=hello becomes
        http://example.com.mydcos.directory:8080/?query=hello).

    vpn
        Establish a VPN over SSH to the master node of your DC/OS cluster.

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
        The SSH user [default: core].
    --verbose
        Verbose output
    --port=<local-port>
        The port to listen on locally
        Defaults to SOCKS:1080, HTTP:80, VPN:1194
    --container=<container>
        The OpenVPN container to run
        [default: dcos/dcos-cli-vpn:2-bcccc2ba3a4d15e24d826deeecbf0601c8f76a4e]
    --client=<path>
        The OpenVPN client to run [default: openvpn]
    --privileged
        Assume the user is of "superuser" or "Administrator" equivalent
    --sport=<ssh_port>
        The port that SSH is listening on
    --host=<host>
        Manually specify which host to connect to (it will override attempts to
        detect which host to connect to)
    --remote-docker=<docker-command>
        The Docker client command to run on the remote DC/OS master
    --addroute <ip-address>
        Add route to IPv4/IPv6 address (e.g. "192.168.1.0"), optionally with subnet (e.g. "192.168.1.0/32")
    --delroute <ip-address>
        Delete route to IPv4/IPv6 address (e.g. "192.168.1.0"), optionally with subnet (e.g. "192.168.1.0/32").
        You must delete with the exact subnet that the range was added with.
"""

import binascii
import distutils.spawn
import ipaddress
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
                      '--sport', '--host', '--verbose', '--option'],
            function=_socks),

        cmds.Command(
            hierarchy=['tunnel', 'http'],
            arg_keys=['--port', '--config-file', '--user', '--privileged',
                      '--sport', '--host', '--verbose'],
            function=_http),

        cmds.Command(
            hierarchy=['tunnel', 'vpn'],
            arg_keys=['--port', '--config-file', '--user', '--privileged',
                      '--sport', '--host', '--verbose', '--container', '--client',
                      '--remote-docker', '--addroute', '--delroute'],
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


def ssh_exec_fatal(client, scom, hint=None):
    _, query_stdout, _ = client.exec_command(scom, get_pty=True)
    if query_stdout.channel.recv_exit_status() == 0:
        return query_stdout
    else:
        msg = '*** Failed to execute: {}'.format(scom)
        if hint:
            msg += '\n*** {}'.format(hint)
        raise DCOSException(msg)


def set_verbose():
    util.configure_logger("debug")


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


def get_host(host):
    if not host:
        dcos_client = mesos.DCOSClient()
        host = dcos_client.metadata().get('PUBLIC_IPV4')
    if not host:
        host = mesos.MesosDNSClient().hosts('leader.mesos.')[0]['ip']
    if not host:
        raise DCOSException("*** No host detected. Please set one manually.")
    return host


def sshclient(config_file, user, port, host):

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

    host = get_host(host)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(CustomWarningPolicy())

    config = parse_config(config_file, host)
    if port is None:
        if config is not None and 'port' in config:
            port = config['port']
        else:
            port = 22
    port = int(port)

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

    config = paramiko.config.SSHConfig()
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


def _socks(port, config_file, user, privileged, ssh_port, host, verbose,
           option):
    """
    SOCKS proxy into a DC/OS node using the IP addresses found in master's
    state.json

    :param port: The port the SOCKS proxy listens on locally
    :type port: int | None
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param privileged: If True, override privilege checks
    :type privileged: bool
    :param ssh_port: The port SSH is accessible through
    :type ssh_port: int | None
    :param host: The host to connect to
    :type host: str | None
    :param verbose: Verbose output
    :type verbose: bool
    :param option: SSH option
    :type option: [str]
    :returns: process return code
    :rtype: int
    """

    if verbose:
        set_verbose()

    if privileged:
        os.environ[constants.privileged] = '1'
    port = validate_port(port, default=1080)
    if port is None:
        return 1

    if ssh_port is not None:
        option.append("Port={}".format(ssh_port))

    ssh_options = util.get_ssh_options(config_file, option)
    host = get_host(host)

    other_options = ''
    if verbose:
        other_options += ' -v'
    scom = "ssh -N -D {} {} {} {}@{}".format(
        port, ssh_options, other_options, user, host)
    logger.debug('SSH command: "%s"', scom)

    emitter.publish('SOCKS proxy listening on port {}'.format(port))
    return subprocess_call(shlex.split(scom))


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


def _http(port, config_file, user, privileged, ssh_port, host, verbose):
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
    :param ssh_port: The port SSH is accessible through
    :type ssh_port: int | None
    :param host: The host to connect to
    :type host: str | None
    :param verbose: Verbose output
    :type verbose: bool
    :returns: process return code
    :rtype: int
    """

    if verbose:
        set_verbose()

    if privileged:
        os.environ[constants.privileged] = '1'
    port = validate_port(port, default=80)
    if port is None:
        return 1
    client = sshclient(config_file, user, ssh_port, host)

    http_proxy = '/opt/mesosphere/bin/octarine'
    proxy_id = rand_str(16)

    # A version was introduced to detect breaking changes in the proxy. As
    # the version command did not always exist, if the command fails it is
    # considered the "pre-version"
    version_scom = "{} --version".format(http_proxy)
    logger.debug("version command: {}".format(version_scom))
    version, exitcode, stderr = must_ssh_query_int(client, version_scom)
    if exitcode != 0:
        msg = "failed to get version, assuming older executable: {}"
        logger.debug(msg.format(stderr))
        version = 0
    logger.debug("proxy version: {}".format(version))

    proxy_scom = http_proxy
    if verbose:
        proxy_scom += ' --verbose'
    if version >= 1:
        if port == 80:
            proxy_scom += " --mode transparent"
        else:
            proxy_scom += " --mode standard"
    proxy_scom += " {}".format(proxy_id)

    logger.debug("proxy command: {}".format(proxy_scom))
    http_proxy_server = threading.Thread(target=logging_exec,
                                         args=(client, proxy_scom, sys.stderr),
                                         daemon=True)
    http_proxy_server.start()

    port_scom = "{} --client --port {}".format(http_proxy, proxy_id)
    logger.debug("port command: {}".format(port_scom))
    remote_port, exitcode, stderr = must_ssh_query_int(client, port_scom)
    if exitcode != 0:
        msg = "*** port query non-zero exit code: {} stderr: {}"
        raise DCOSException(msg.format(exitcode, stderr))

    msg = 'HTTP proxy listening locally on port {}, remotely on port {}'
    emitter.publish(msg.format(port, remote_port))
    forward_tunnel(port, '127.0.0.1', remote_port, client.get_transport())

    client.close()
    return 0


def must_ssh_query_int(ssh_client, ssh_command):
    res_int = None
    query_success = False
    for i in range(5):
        # XXX There's a really strange bug where stderr is bleeding into
        #   stdout. What occurs is that a single line of the stderr sneaks
        #   into stdout along with the intended stdout. Since this isn't a
        #   problem with this code, we'll just retry several times.

        _, stdout, stderr = ssh_client.exec_command(ssh_command, get_pty=True)
        stdout_str = stdout.read().decode().strip()
        stderr_str = stderr.read().decode().strip()
        exitcode = stdout.channel.recv_exit_status()
        if exitcode != 0:
            return (res_int, exitcode, stderr_str)

        try:
            res_int = int(stdout_str)
            query_success = True
        except ValueError as e:
            msg = "*** ssh query int failed cmd: {} res: {}"
            logger.error(msg.format(ssh_command, repr(e)))

        if query_success:
            break

    if not query_success:
        msg = "*** Too many errors during ssh query int cmd: {}"
        raise DCOSException(msg.format(ssh_command))
    return (res_int, exitcode, stderr_str)


def is_privileged():
    return (os.geteuid() == 0) or (os.environ.get(constants.privileged) == '1')


def rand_str(n):
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.SystemRandom().choice(choices) for _ in range(n))


class VPNHost(object):
    def __init__(self, ssh_client, r_addroute, r_delroute):
        self.dcos_client = mesos.DCOSClient()
        self.dns_client = mesos.MesosDNSClient()
        self.ssh_client = ssh_client
        self.addroute = marshal_networks(r_addroute)
        self.delroute = marshal_networks(r_delroute)

    def gen_hosts(self):
        """
        route_hosts: Set of strings of form "ip_address netmask"
        dns_hosts: Set of strings of form "ip_address"
        """

        dns_hosts = self.gen_dns_hosts(self.delroute)
        route_hosts = self.gen_route_hosts(self.addroute+dns_hosts, self.delroute)

        route_host_strs = set()
        for h in route_hosts:
            addr = h.network_address.exploded
            netmask = h.netmask.exploded
            route_host_strs.add("{} {}".format(addr, netmask))

        dns_host_strs = set()
        for h in dns_hosts:
            dns_host_strs.add(h.network_address.exploded)

        return (sorted(list(route_host_strs)), sorted(list(dns_host_strs)))

    def gen_route_hosts(self, addroute, delroute):
        r_route_hosts = []

        for host in self.dns_client.hosts('master.mesos.'):
            r_route_hosts.append(host['ip'])

        summary = self.dcos_client.get_state_summary()
        for host in summary['slaves']:
            r_route_hosts.append(host['hostname'])

        networks = marshal_networks(r_route_hosts)
        return filter_networks(networks+addroute, delroute)

    def gen_dns_hosts(self, delroute):
        r_dns_hosts = []

        scom = 'cat /etc/resolv.conf'
        _, query_stdout, _ = self.ssh_client.exec_command(scom, get_pty=True)
        for line in query_stdout.readlines():
            if line.startswith('nameserver'):
                host = line.strip().split()[1]
                r_dns_hosts.append(host)
        networks = marshal_networks(r_dns_hosts)
        return filter_networks(networks, delroute)


def marshal_networks(raw_networks):
    networks = []
    for a in raw_networks:
        try:
            networks.append(ipaddress.ip_network(a))
        except ValueError:
            logger.error("*** Failed to marshall addr: {}".format(repr(a)))
    return networks


def filter_networks(inputlist, cutset):
    """
    This only deletes from the inputlist if the exact address and netmask
    in the cutset matches.

    This has the disadvantage of not allowing fine-grained deletion of IP
    addresses. A considered alternative was flattening (enumerating subnets
    into individual IP addresses), but that is not feasible with the
    possible number of IPv6 addresses.
    """

    outputlist = []
    for e in inputlist:
        accept = True
        for c in cutset:
            if e.exploded == c.exploded:
                accept = False
        if accept:
            outputlist.append(e)
    logger.info("filter_networks input: {}".format(repr(inputlist)))
    logger.info("filter_networks cutset: {}".format(repr(cutset)))
    logger.info("filter_networks outputlist: {}".format(repr(outputlist)))
    return outputlist


def container_cp(ssh_client, container_name, remote_filepath, local_file,
                 docker_cmd):
    scom = '{} exec {} bash -c "cat {}"'
    scom = scom.format(docker_cmd, container_name, remote_filepath)
    os.write(local_file, ssh_exec_fatal(ssh_client, scom).read())
    os.fsync(local_file)


def run_vpn(command, output_file):
    return subprocess_call(shlex.split(command),
                           stdout=output_file,
                           stderr=output_file)


def resolve_docker_cmd(client, docker_cmd):
    try_sudo = False
    if docker_cmd is None:
        docker_cmd = 'docker'
        try_sudo = True
    hint = "`{}` not a valid Docker client".format(docker_cmd)

    ok, err = valid_docker_cmd(client, docker_cmd, hint)
    if ok:
        return docker_cmd
    if try_sudo:
        hint = ("Unable to run `docker` or `sudo docker` on the remote " +
                "master. Try specifying a custom Docker client command " +
                "using the --remote-docker argument.")
        docker_cmd = 'sudo --non-interactive docker'
        ok, err = valid_docker_cmd(client, docker_cmd, hint)
        if ok:
            return docker_cmd
        docker_cmd = 'sudo -n docker'
        ok, err = valid_docker_cmd(client, docker_cmd, hint)
        if ok:
            return docker_cmd
    raise err


def valid_docker_cmd(client, docker_cmd, hint):
    scom = '{} version'.format(docker_cmd)
    try:
        ssh_exec_fatal(client, scom, hint=hint)
    except DCOSException as e:
        return (False, e)
    return (True, None)


def _vpn(port, config_file, user, privileged, ssh_port, host, verbose,
         openvpn_container, vpn_client, docker_cmd, addroute, delroute):
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
    :param ssh_port: The port SSH is accessible through
    :type ssh_port: int | None
    :param host: The host to connect to
    :type host: str | None
    :param verbose: Verbose output
    :type verbose: bool
    :param openvpn_container: `docker pull <param>` should work
    :type openvpn_container: str
    :param vpn_client: Relative or absolute path to openvpn client
    :type vpn_client: str
    :param docker_cmd: The docker client command
    :type docker_cmd: str | None
    :param addroute: Add route to IPv4/IPv6 address with optional subnet
    :type option: [str]
    :param delroute: Delete route to IPv4/IPv6 address with optional subnet
    :type option: [str]
    :returns: process return code
    :rtype: int
    """

    if verbose:
        set_verbose()

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
    client = sshclient(config_file, user, ssh_port, host)

    if not distutils.spawn.find_executable(vpn_client):
        msg = ("You don't seem to have the '{}' executable. Please add it to "
               "your $PATH or equivalent.")
        logger.error(msg.format(vpn_client))
        return 1

    docker_cmd = resolve_docker_cmd(client, docker_cmd)

    route_hosts, dns_hosts = VPNHost(client, addroute, delroute).gen_hosts()
    container_name = "openvpn-{}".format(rand_str(8))
    remote_openvpn_dir = "/etc/openvpn"
    remote_keyfile = "{}/static.key".format(remote_openvpn_dir)
    remote_clientfile = "{}/client.ovpn".format(remote_openvpn_dir)

    emitter.publish("\nATTENTION: IF DNS DOESN'T WORK, add these DNS servers!")
    for host in dns_hosts:
        emitter.publish(host)

    parsed_routes = ','.join(route_hosts)
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
               {} run --rm --cap-add=NET_ADMIN -p 0:1194 \
               -e "OPENVPN_ROUTES={}" -e "OPENVPN_DNS={}" --name {} {}\
               """.format(docker_cmd, parsed_routes, parsed_dns,
                          container_name, openvpn_container)

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
                """[ "$(%s inspect --format='{{ .State.Running }}' """
                """%s 2>/dev/null)" = "true" ] 2>/dev/null; do sleep 0.5; """
                """done""") % (docker_cmd, container_name)
        scom += (" && "
                 """{} exec {} sh -c 'until [ -s {} ]; do sleep 0.5; """
                 """done' """).format(docker_cmd, container_name,
                                      remote_keyfile)
        scom += (" && "
                 """{} exec {} sh -c 'until [ -s {} ]; do sleep 0.5; """
                 """done' """).format(docker_cmd, container_name,
                                      remote_clientfile)
        ssh_exec_fatal(client, scom)

        scom = ("""%s inspect --format='"""
                """{{range $p, $conf := .NetworkSettings.Ports}}"""
                """{{(index $conf 0).HostPort}}{{end}}' %s"""
                ) % (docker_cmd, container_name)
        remote_port = int(ssh_exec_fatal(client, scom).read().decode().strip())

        def tunnel_def():
            ssh_transport = client.get_transport()
            forward_tunnel(port, '127.0.0.1', remote_port, ssh_transport)
        tunnel = threading.Thread(target=tunnel_def, daemon=True)
        tunnel.start()

        container_cp(client, container_name, remote_keyfile, keyfile,
                     docker_cmd)
        container_cp(client, container_name, remote_clientfile,
                     clientconfigfile, docker_cmd)

        vpn_com = '{} --config {} --secret {} --port {}'
        vpn_com = vpn_com.format(vpn_client, clientconfigpath, keypath, port)
        logger.info("Running VPN command: {}".format(vpn_com))

        emitter.publish("\nVPN server output at {}".format(serverpath))
        emitter.publish("VPN client output at {}\n".format(clientpath))
        ret = run_vpn(vpn_com, clientfile)

        client.close()
        input('Exited. Temporary files will be gone once you hit <Return>.')
        return ret


def subprocess_call(args, stdout=None, stderr=None):
    """
    THIS MUST BE USED INSTEAD OF subprocess
    """

    # https://github.com/pyinstaller/pyinstaller/issues/1759
    #
    # Pyinstaller insists on setting LD_LIBRARY_PATH. As a workaround for
    # applications that care about this variable, they also set
    # LD_LIBRARY_PATH_ORIG. We will take their suggestion of flipping this
    # back around.

    env = os.environ.copy()

    ld_path = "LD_LIBRARY_PATH"
    ld_path_orig = "{}_ORIG".format(ld_path)
    if ld_path_orig in env:
        env[ld_path] = env[ld_path_orig]
        del env[ld_path_orig]
    elif ld_path in env:
        del env[ld_path]

    return subprocess.call(args, stdout=stdout, stderr=stderr, env=env)


if __name__ == "__main__":
    main()
