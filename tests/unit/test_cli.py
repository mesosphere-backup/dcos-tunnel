import ipaddress

from dcos_tunnel import cli


class GenHostsSSHClient(object):
    def __init__(self, scom):
        self.scom = scom

    def exec_command(self, ignored_scom, get_pty=None):
        return (None, GenHostsFile(self.scom), None)


class GenHostsFile(object):
    def __init__(self, s):
        self.s = s

    def readlines(self):
        return self.s.splitlines()


class GenHostsDNSClient(object):
    def __init__(self, s):
        self.s = s

    def hosts(self, ignored):
        return self.s


class GenHostsDcosClient(object):
    def __init__(self, s):
        self.s = s

    def get_state_summary(self):
        return self.s


def test_marshal_networks():
    addrs = ["192.168.1.0"]
    a = cli.marshal_networks(addrs)
    assert isinstance(a[0], ipaddress.IPv4Network)

    addrs = ["2001:db00::0"]
    a = cli.marshal_networks(addrs)
    assert isinstance(a[0], ipaddress.IPv6Network)

    addrs = ["blah"]
    a = cli.marshal_networks(addrs)
    assert len(a) == 0


def test_filter_networks_equality():
    inputlist = cli.marshal_networks(["192.168.1.0", "192.168.1.0/32", "192.168.1.0/255.255.255.255"])
    cutset = cli.marshal_networks(["192.168.1.0"])

    filtered = cli.filter_networks(inputlist, [])
    assert filtered == inputlist

    filtered = cli.filter_networks(inputlist, cutset)
    assert len(filtered) == 0


def test_filter_networks_mixed_addressing():
    inputlist = cli.marshal_networks(["192.168.1.0", "2001:db00::0"])
    cutset = cli.marshal_networks(["192.168.1.0", "2001:db00::0"])

    filtered = cli.filter_networks(inputlist, [])
    assert filtered == inputlist

    filtered = cli.filter_networks(inputlist, cutset)
    assert len(filtered) == 0


def test_gen_hosts():
    addv4 = ["192.168.1.0", "192.168.2.0", "0.0.0.0", "255.255.255.255"]
    delv4 = ["192.168.1.0", "0.0.0.0"]
    addv6 = ["2001:db00::0", "2001:db00::1111",
             "0000:0000:0000:0000:0000:0000:0000:0000",
             "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
    delv6 = ["2001:db00::1111", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]

    fakeclient = GenHostsSSHClient("nameserver 198.51.100.1\nnameserver 198.51.100.2\nnameserver 198.51.100.3\n")

    expected_route_hosts_v4 = ["192.168.2.0", "255.255.255.255", "198.51.100.1",
                               "198.51.100.2", "198.51.100.3", "1.1.1.1", "2.2.2.2"]
    expected_route_hosts_v4 = ["{} 255.255.255.255".format(x) for x in expected_route_hosts_v4]
    expected_route_hosts_v6 = ["2001:db00:0000:0000:0000:0000:0000:0000", "0000:0000:0000:0000:0000:0000:0000:0000"]
    expected_route_hosts_v6 = ["{} ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".format(x) for x in expected_route_hosts_v6]

    expected_dns_hosts = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]

    vpnhost = cli.VPNHost(fakeclient, addv4+addv6, delv4+delv6)
    vpnhost.dcos_client = GenHostsDcosClient({'slaves': [{'hostname': '1.1.1.1'}]})
    vpnhost.dns_client = GenHostsDNSClient([{'ip': '2.2.2.2'}])
    route_hosts, dns_hosts = vpnhost.gen_hosts()
    assert sorted(route_hosts) == sorted(expected_route_hosts_v4+expected_route_hosts_v6)
    assert sorted(dns_hosts) == sorted(expected_dns_hosts)
