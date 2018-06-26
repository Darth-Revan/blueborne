"""
This module handles the creation of basic bluetooth sockets via L2CAP.
"""

# No direct invocation of this module
if __name__ == "__main__":
    import sys
    sys.exit("This module must not be invoked directly. Invoke exploit.py instead.")

import socket
import utility_stuff as utils

# from /usr/include/bluetooth/bluetooth.h and /usr/include/bluetooth/l2cap.h
# Used for getting/setting the socket options for L2CAP sockets
SOL_L2CAP = 6
L2CAP_OPTIONS = 1

_pack_l2cap_options, _unpack_l2cap_options, _sizeof_l2cap_options = \
    utils.create_struct_funcs('', (
        ('omtu', 'H'),
        ('imtu', 'H'),
        ('flush_to', 'H'),
        ('mode', 'B'),
        ('fcs', 'B'),
        ('max_tx', 'B'),
        ('txwin_size', 'H'),
    ))

def l2cap_connect(dst, src=None, mtu=None):
    """
    Create a L2CAP socket and connect to 'dst'.

    Params:
        - 'dst' - The target device to connect to
        - 'src' - If not 'None', bind the socket to this address
        - 'mtu' - If not 'None', set the MTU of the connection to this value

    Returns:
        The newly created socket handle
    """
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    if src is not None:
        sock.bind(src)
    if mtu is not None:
        set_imtu(sock, mtu)
    sock.connect(dst)
    return sock

def get_l2cap_options(sock):
    """
    Returns the options of a L2CAP socket.

    Params:
        - 'sock' - Handle of a L2CAP socket

    Returns:
        Options of the socket as a dictionary
    """
    return _unpack_l2cap_options(sock.getsockopt(SOL_L2CAP, L2CAP_OPTIONS,
                                                 _sizeof_l2cap_options()))

def set_l2cap_options(sock, options):
    """
    Sets the options of a L2CAP socket to 'options'.

    Params:
        - 'sock' - Socket to set the options of
        - 'options' - Options for the socket as dictionary
    """
    value = _pack_l2cap_options(**options)
    sock.setsockopt(SOL_L2CAP, L2CAP_OPTIONS, value)

def get_imtu(sock):
    """
    Returns the MTU of the socket handle 'sock'.

    Params:
        - 'sock' - Socket handle to return the MTU of

    Returns:
        MTU of the socket 'sock'
    """
    return get_l2cap_options(sock)['imtu']

def set_imtu(sock, imtu):
    """
    Sets the MTU of 'sock' to 'imtu'.

    Params:
        - 'sock' - The socket handle to set the MTU of
        - 'imtu' - The new MTU for the socket
    """
    options = get_l2cap_options(sock)
    options['imtu'] = imtu
    set_l2cap_options(sock, options)
