# DC/OS Tunnel Subcommand

A DC/OS subcommand that provides SOCKS proxy, HTTP proxy, and VPN access
to your DC/OS cluster.

<br>
This is **NOT** meant as a standalone but as an _installable subcommand_ through
the _DC/OS Universe_.
<br>
<br>

## Development Setup
Clone the git repo:
```
git clone git@github.com:dcos/dcos-tunnel.git
```

Change directory to the repo directory:

```
cd dcos-tunnel
```

Make sure that you have python `virtualenv` installed.

Create a virtualenv for the project:

```
make env
```

##Binary

```
make local-binary
```

Run it with:

```
./dist/dcos-tunnel
```


##Running Tests

###Setup

Tox, our test runner, tests against both Python 2.7 and Python 3.4 environments.

If you're using OS X, be sure to use the officially distributed Python 3.4 installer since the
Homebrew version is missing a necessary library.

###Running

Tox will run unit and integration tests in both Python environments using a temporarily created
virtualenv.

You should ensure `DCOS_CONFIG` is set and that the config file points to the Marathon
instance you want to use for integration tests.

There are two ways to run tests, you can either use the virtualenv created by `make env`
above:

```
make test
```

Or, assuming you have tox installed:

```
tox
```

##Other Useful Commands

List all of the supported test environments:

```
tox --listenvs
```

Run a specific set of tests:

```
tox -e <testenv>
```
