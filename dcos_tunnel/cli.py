"""
Description:
    SOCKS proxy, HTTP proxy, and VPN access to a DC/OS cluster.

Usage:
    dcos tunnel --info
    dcos tunnel socks [--port=<local-port>]
                      [--option SSHOPT=VAL ...]
                      [--config-file=<path>]
                      [--user=<user>]
                      [--master-proxy]
    dcos tunnel http [--port=<local-port>]
                     [--option SSHOPT=VAL ...]
                     [--config-file=<path>]
                     [--user=<user>]
                     [--master-proxy]
                     [--verbose]
    dcos tunnel vpn [--port=<local-port>]
                    [--option SSHOPT=VAL ...]
                    [--config-file=<path>]
                    [--user=<user>]
                    [--master-proxy]
                    [--container=<container>]

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
    --master-proxy
        Proxy the SSH connection through a master node. This can be useful
        when accessing DC/OS from a separate network. For example, in the
        default AWS configuration, the private slaves are unreachable from
        the public internet. You can access them using this option, which
        will first hop from the publicly available master.
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

Positional Arguments:
    <command>
        Command to execute on the DCOS cluster node.
"""

import distutils.spawn
import getpass
import os
import random
import shlex
import signal
import string
import subprocess
import sys

import docopt
from dcos import cmds, emitting, mesos, util
from dcos.errors import DCOSException, DefaultError
from dcos_tunnel import constants

logger = util.get_logger(__name__)
emitter = emitting.FlatEmitter()


def signal_handler(signal, frame):
    emitter.publish(DefaultError("User interrupted command with Ctrl-C"))
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = docopt.docopt(
        __doc__,
        version=constants.version)

    return cmds.execute(_cmds(), args)


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
            arg_keys=['--port', '--option', '--config-file', '--user',
                      '--master-proxy'],
            function=_socks),

        cmds.Command(
            hierarchy=['tunnel', 'http'],
            arg_keys=['--port', '--option', '--config-file', '--user',
                      '--master-proxy', '--verbose'],
            function=_http),

        cmds.Command(
            hierarchy=['tunnel', 'vpn'],
            arg_keys=['--port', '--option', '--config-file', '--user',
                      '--master-proxy', '--container'],
            function=_vpn),
    ]


def _info():
    """Print node cli information.

    :returns: process return code
    :rtype: int
    """

    emitter.publish("Proxy and VPN access to DC/OS cluster")
    return 0


def _ssh(leader, slave, option, config_file, user, master_proxy, command,
         flag=[], print_command=True, short_circuit=False, output=False,
         output_dst=None, tty=True, raw=False):
    """SSH into a DCOS node using the IP addresses found in master's
       state.json

    :param leader: True if the user has opted to SSH into the leading
                   master
    :type leader: bool | None
    :param slave: The slave ID if the user has opted to SSH into a slave
    :type slave: str | None
    :param option: SSH option
    :type option: [str]
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param master_proxy: If True, SSH-hop from a master
    :type master_proxy: bool | None
    :param command: Command to run on the node
    :type command: str | None
    :param flag: SSH flags
    :type flag: [str]
    :param print_command: If True, print the raw SSH command
    :type print_command: bool
    :param short_circuit: Only use the first SSH connection made
    :type short_circuit: bool
    :param output: If True, return the output of the ssh command
    :type output: boolean
    :param output_dst: Where to send the output of SSH
    :type output_dst: object | None
    :param tty: If True, have SSH allocate a TTY
    :type tty: boolean
    :param raw: If True, return a subprocess.Popen object
    :type raw: boolean
    :rtype: int
    :returns: process return code | str
    """

    ssh_options = util.get_ssh_options(config_file, option)
    dcos_client = mesos.DCOSClient()
    flagstr = " ".join(flag)

    if tty:
        flagstr += ' -t'
    else:
        flagstr += ' -T'

    if leader:
        host = mesos.MesosDNSClient().hosts('leader.mesos.')[0]['ip']
    else:
        summary = dcos_client.get_state_summary()
        slave_obj = next((slave_ for slave_ in summary['slaves']
                          if slave_['id'] == slave),
                         None)
        if slave_obj:
            host = mesos.parse_pid(slave_obj['pid'])[1]
        else:
            raise DCOSException('No slave found with ID [{}]'.format(slave))

    if command is None:
        command = ''

    master_public_ip = dcos_client.metadata().get('PUBLIC_IPV4')
    if master_proxy:
        if not os.environ.get('SSH_AUTH_SOCK'):
            raise DCOSException(
                "There is no SSH_AUTH_SOCK env variable, which likely means "
                "you aren't running `ssh-agent`.  `dcos node ssh "
                "--master-proxy` depends on `ssh-agent` to safely use your "
                "private key to hop between nodes in your cluster.  Please "
                "run `ssh-agent`, then add your private key with `ssh-add`.")
        if not master_public_ip:
            raise DCOSException(("Cannot use --master-proxy.  Failed to find "
                                 "'PUBLIC_IPV4' at {}").format(
                                     dcos_client.get_dcos_url('metadata')))

        cmd = "ssh -A {0} {1}{2}@{3} ssh {0} {1}{2}@{4} {5}"
        if short_circuit:
            cmd = "ssh -A {0} {1}{2}@{3} {5}"
        cmd = cmd.format(
            flagstr,
            ssh_options,
            user,
            master_public_ip,
            host,
            command)
    else:
        cmd = "ssh {0} {1}{2}@{3} {4}".format(
            flagstr,
            ssh_options,
            user,
            host,
            command)

    if print_command:
        emitter.publish(DefaultError("Running `{}`".format(cmd)))
    if (not master_proxy) and master_public_ip:
        emitter.publish(
            DefaultError("If you are running this command from a separate "
                         "network than DC/OS, consider using "
                         "`--master-proxy`"))

    cmd = shlex.split(cmd)
    if output:
        return subprocess.check_output(cmd)
    if raw:
        if output_dst is not None:
            return subprocess.Popen(cmd, stderr=output_dst, stdout=output_dst)
        return subprocess.Popen(cmd)
    if output_dst is not None:
        return subprocess.call(cmd, stderr=output_dst, stdout=output_dst)
    return subprocess.call(cmd)


def _socks(port, option, config_file, user, master_proxy):
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
    :param master_proxy: If True, SSH-hop from a master
    :type master_proxy: bool | None
    :returns: process return code
    :rtype: int
    """

    if port is None:
        port = 1080

    emitter.publish('SOCKS proxy listening on port {}'.format(port))
    return _ssh(True, None, option, config_file, user, master_proxy, None,
                flag=['-N', '-D {}'.format(port)], print_command=False,
                short_circuit=True, tty=False)


def _http(port, option, config_file, user, master_proxy, verbose):
    """
    Proxy HTTP traffic into a DC/OS cluster using the IP addresses found in
        master's state.json

    :param port: The port the HTTP proxy listens on locally
    :type port: int | None
    :param option: SSH option
    :type option: [str]
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param master_proxy: If True, SSH-hop from a master
    :type master_proxy: bool | None
    :param verbose: Verbose output
    :type verbose: bool
    :returns: process return code
    :rtype: int
    """

    if port is None:
        port = 80

    http_proxy = '/opt/mesosphere/bin/octarine'
    proxy_id = rand_str(16)

    scom = http_proxy
    if verbose:
        scom += ' --verbose'
    scom += " {0}".format(proxy_id)
    proxy = _ssh(True, None, option, config_file, user, master_proxy, scom,
                 print_command=False, short_circuit=True, tty=False, raw=True)

    scom = "{0} --client --port {1}".format(http_proxy, proxy_id)
    remote_port = _ssh(True, None, option, config_file, user, master_proxy,
                       scom, print_command=False, short_circuit=True,
                       output=True, tty=False)

    msg = 'HTTP proxy listening locally on port {0}, remotely on port {1}'
    emitter.publish(msg.format(port, remote_port))
    fwd_flag = '-N -L {0}:127.0.0.1:{1}'.format(port, remote_port)
    ret = _ssh(True, None, option, config_file, user, master_proxy, None,
               flag=[fwd_flag], print_command=False, short_circuit=True,
               tty=False)

    proxy.communicate()
    return ret


def is_privileged():
    return os.geteuid() == 0


def rand_str(n):
    return ''.join(
            random.SystemRandom().choice(string.ascii_lowercase+string.digits)
            for _ in range(n))


def gen_hosts(option, config_file, user, master_proxy):
    dcos_client = mesos.DCOSClient()
    mesos_hosts = []
    dns_hosts = []

    for host in mesos.MesosDNSClient().hosts('master.mesos.'):
        mesos_hosts.append(host['ip'])

    summary = dcos_client.get_state_summary()
    for host in summary['slaves']:
        mesos_hosts.append(host['hostname'])

    scom = 'cat /etc/resolv.conf'
    output = _ssh(True, None, option, config_file, user, master_proxy, scom,
                  print_command=False, short_circuit=True, output=True,
                  tty=False)
    for line in output.splitlines():
        if line.startswith('nameserver'):
            host = line.strip().split()[1]
            dns_hosts.append(host)

    return (mesos_hosts, dns_hosts)


def container_cp(option, config_file, user, master_proxy,
                 container_name, remote_filepath, local_file):

    scom = 'docker exec {0} "cat {1}"'
    scom = scom.format(container_name, remote_filepath)
    output = _ssh(True, None, option, config_file, user, master_proxy,
                  scom, print_command=False, short_circuit=True,
                  output=True, tty=False)
    os.write(local_file, output)
    os.fsync(local_file)


def _vpn(port, option, config_file, user, master_proxy, openvpn_container):
    """
    VPN into a DC/OS cluster using the IP addresses found in master's
       state.json

    :param port: The port the HTTP proxy listens on locally
    :type port: int | None
    :param option: SSH option
    :type option: [str]
    :param config_file: SSH config file
    :type config_file: str | None
    :param user: SSH user
    :type user: str | None
    :param master_proxy: If True, SSH-hop from a master
    :type master_proxy: bool | None
    :returns: process return code
    :rtype: int
    """

    if sys.platform == 'win32':
        emitter.publish("VPN is currently unsupported on Windows")
        return

    if port is None:
        port = 1194

    vpn_client = 'openvpn'
    if not distutils.spawn.find_executable(vpn_client):
        msg = ("You don't seem to have the '{0}' executable. Please add it to "
               "your $PATH or equivalent.")
        emitter.publish(msg.format(vpn_client))
        return 1

    # The reason I ask for sudo here instead of when it's actually needed,
    # is that there is something messing with stdin once the docker tunnel
    # ssh command is run
    if not is_privileged():
        emitter.publish("You don't have permission to run this "
                        "command. Attempting to increase privileges...")
        FNULL = open(os.devnull, 'w')
        subprocess.call(['sudo', '-l'], stdout=FNULL, stderr=FNULL)
        FNULL.close()

    mesos_hosts, dns_hosts = gen_hosts(option, config_file, user, master_proxy)
    container_name = "openvpn-{0}".format(rand_str(8))
    remote_openvpn_dir = "/etc/openvpn"
    remote_keyfile = "{0}/static.key".format(remote_openvpn_dir)
    remote_clientfile = "{0}/client.ovpn".format(remote_openvpn_dir)

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
               -e "OPENVPN_ROUTES={0}" -e "OPENVPN_DNS={1}" --name {2} {3}\
               """.format(parsed_routes, parsed_dns, container_name,
                          openvpn_container)

        vpn_server = _ssh(True, None, option, config_file, user, master_proxy,
                          scom, print_command=False, short_circuit=True,
                          output_dst=serverfile, tty=False, raw=True)

        msg = "\nWaiting for VPN server in container '{0}' to come up..."
        emitter.publish(msg.format(container_name))
        scom = ("until "
                """[ "$(docker inspect --format='{{ .State.Running }}' """
                """%s 2>/dev/null)" = "true" ] 2>/dev/null; do sleep 0.5; """
                """done""") % (container_name)
        scom += (";"
                 """docker exec {0} "sh -c 'until [ -s {1} ]; do sleep 0.5; """
                 """done'" """).format(container_name, remote_keyfile)
        scom += (";"
                 """docker exec {0} "sh -c 'until [ -s {1} ]; do sleep 0.5; """
                 """done'" """).format(container_name, remote_clientfile)
        _ssh(True, None, option, config_file, user, master_proxy, scom,
             print_command=False, short_circuit=True, tty=False)

        scom = ('"'
                """docker inspect --format='"""
                """{{range $p, $conf := .NetworkSettings.Ports}}"""
                """{{(index $conf 0).HostPort}}{{end}}' %s"""
                '"') % (container_name)
        remote_port = _ssh(True, None, option, config_file, user, master_proxy,
                           scom, print_command=False, short_circuit=True,
                           output=True, tty=False)

        fwd_flag = '-N -L {0}:127.0.0.1:{1}'.format(port, remote_port)
        tunnel = _ssh(True, None, option, config_file, user, master_proxy,
                      None, flag=[fwd_flag], print_command=False,
                      short_circuit=True, tty=False, raw=True)

        container_cp(option, config_file, user, master_proxy,
                     container_name, remote_keyfile, keyfile)
        container_cp(option, config_file, user, master_proxy,
                     container_name, remote_clientfile, clientconfigfile)

        vpn_com = ('openvpn ' +
                   '--config {0} --secret {1} --port {2} --user {3}')
        vpn_com = vpn_com.format(clientconfigpath, keypath, port,
                                 getpass.getuser())
        if not is_privileged():
            vpn_com = 'sudo -n {0}'.format(vpn_com)

        emitter.publish("\nVPN server output at {0}".format(serverpath))
        emitter.publish("VPN client output at {0}\n".format(clientpath))

        ret = subprocess.call(shlex.split(vpn_com), stdout=clientfile,
                              stderr=clientfile)

        vpn_server.communicate()
        tunnel.communicate()
    return ret


if __name__ == "__main__":
    main()
