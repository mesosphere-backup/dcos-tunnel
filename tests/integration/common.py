import os
import pty
import subprocess
import time


def exec_command(cmd, env=None, stdin=None):
    """Execute CLI command

    :param cmd: Program and arguments
    :type cmd: list of str
    :param env: Environment variables
    :type env: dict of str to str
    :param stdin: File to use for stdin
    :type stdin: file
    :returns: A tuple with the returncode, stdout and stderr
    :rtype: (int, bytes, bytes)
    """

    print('CMD: {!r}'.format(cmd))

    process = subprocess.Popen(
        cmd,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env)

    stdout, stderr = process.communicate()

    # We should always print the stdout and stderr
    print('STDOUT: {!r}'.format(stdout.decode('utf-8')))
    print('STDERR: {!r}'.format(stderr.decode('utf-8')))

    return (process.returncode, stdout, stderr)


def popen_tty(cmd):
    """Open a process with stdin connected to a pseudo-tty.  Returns a

    :param cmd: command to run
    :type cmd: str
    :returns: (Popen, master) tuple, where master is the master side
       of the of the tty-pair.  It is the responsibility of the caller
       to close the master fd, and to perform any cleanup (including
       waiting for completion) of the Popen object.
    :rtype: (Popen, int)

    """
    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd,
                            stdin=slave,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            preexec_fn=os.setsid,
                            close_fds=True,
                            shell=True)
    os.close(slave)

    return (proc, master)


def ssh_output(cmd, timeout=3):
    """
    Runs an SSH command and returns the stdout/stderr/returncode.

    :param cmd: command to run
    :type cmd: str
    :rtype: (str, str, int)
    """

    print('SSH COMMAND: {}'.format(cmd))

    # ssh must run with stdin attached to a tty
    proc, master = popen_tty(cmd)

    # wait for the ssh connection
    time.sleep(timeout)

    proc.poll()
    returncode = proc.returncode

    # kill the whole process group
    try:
        os.killpg(os.getpgid(proc.pid), 15)
    except OSError:
        pass

    os.close(master)
    stdout, stderr = proc.communicate()

    print('SSH STDOUT: {}'.format(stdout.decode('utf-8')))
    print('SSH STDERR: {}'.format(stderr.decode('utf-8')))

    return stdout, stderr, returncode
