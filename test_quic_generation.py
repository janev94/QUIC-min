import socket
from quicPacket import QuicPacket
import binascii

from collections import OrderedDict
import struct


def generate_QUIC_packet(con_id = -1):
    flags = QuicPacket.gen_public_flags()
    if con_id == -1:
        con_id = QuicPacket.gen_con_id()
    else:
        con_id_hex = hex(con_id)[2:]
        # Sometimes the con_id number is of type 'long'
        if con_id_hex.endswith('L'):
            con_id_hex = con_id_hex[:-1]
        con_id = [int(con_id_hex[i: i+2], 16) for i in range(0, len(con_id_hex), 2)]
        con_id = bytearray(con_id)
    ver = QuicPacket.gen_version_bytes()
    packet_no = QuicPacket.gen_packet_number()

    stream_hdr = QuicPacket.gen_stream_frame_hdr()
    
    chlo_content = QuicPacket.gen_client_hello_data()

    forged_payload = QuicPacket.forgePayload()    

    result = bytearray([]).join(x for x in [flags, con_id, ver, packet_no, forged_payload]) #, stream_hdr, chlo_content])

    return (result, con_id)



quic_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

(payload, con_id) = generate_QUIC_packet(15686161556997152859)

print binascii.hexlify(payload)


import random

import quic_utils

(pl, cid) = quic_utils.craft_QUIC_packet(15686161556997152859)


print cid == con_id

print cid
print con_id

send = True

if send:
    quic_socket.settimeout(1)

    quic_socket.sendto(payload, ('216.58.207.35', 443))

    reply = quic_socket.recvfrom(1024)

    print len(reply)

    quic_socket.sendto(pl, ('216.58.207.35', 443))

    reply = quic_socket.recvfrom(1024)

    print len(reply)





