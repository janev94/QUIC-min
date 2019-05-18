import binascii
import struct
import random
from collections import OrderedDict

verbose = False

PUBLIC_FLAG_VERSION = 0x01
PUBLIC_FLAG_RESET = 0x02
PUBLIC_FLAG_DIVERSIFICATION_NONCE = 0x04
PUBLIC_FLAG_CONNECTION_ID_8_BYTES = 0x08
PUBLIC_FLAG_PACKET_NUMBER_1_BYTE = 0x00
PUBLIC_FLAG_PACKET_NUMBER_2_BYTE = 0x10
PUBLIC_FLAG_PACKET_NUMBER_4_BYTE = 0x20
PUBLIC_FLAG_PACKET_NUMBER_6_BYTE = 0x30

class PublicHeader:
    """Public QUIC packet header."""

    def __init__(self, cid, version=b'Z036'):
        self.public_flags = PUBLIC_FLAG_VERSION \
            | PUBLIC_FLAG_CONNECTION_ID_8_BYTES \
            | PUBLIC_FLAG_PACKET_NUMBER_1_BYTE

        if verbose:
            print "flags %d" % self.public_flags
        if cid:
            self.cid = cid
        else:
            self.cid = b''
        self.version = b'Z036'
        self.diversification_nonces = []
        self.packet_number = 1

    def to_bytes(self):
        """Serializes public header to bytes array."""
        if verbose:
            print 'serializing pub hdrs'
            print self.cid
            print binascii.hexlify(struct.pack('>Q', self.cid))
        return struct.pack('B', self.public_flags) + struct.pack('>Q', self.cid) + self.version + struct.pack('B', self.packet_number)


FRAME_FLAG_STREAM = 0x80
FRAME_FLAG_STREAM_FINISHED = 0x40
FRAME_FLAG_STREAM_DATA_LENGTH_PRESENT = 0x20
FRAME_FLAG_STREAM_DATA_OFFSET_LENGTH = 0x1C
FRAME_FLAG_STREAM_ID_LENGTH = 0x03


class StreamHdr():


    def __init__(self, id, has_data_length, data_length, id_length):
        self.id = id
        self.has_data_length = has_data_length
        self.data_length = data_length
        self.id_length = id_length

        #NON_CONFIG
        self.finish = False
        self.offset_length = 0


    def to_bytes(self):
        """Serializes stream frame header to byte array."""
        buff = self._serialized_type_byte() + struct.pack('B', self.id) 

        if self.has_data_length:
            buff += struct.pack('>H', self.data_length)

        return buff


    def _serialized_type_byte(self):
        """Serializes the stream frame type byte."""
        flags = FRAME_FLAG_STREAM

        if self.finish:
            flags |= FRAME_FLAG_STREAM_FINISHED

        if self.has_data_length:
            flags |= FRAME_FLAG_STREAM_DATA_LENGTH_PRESENT

        if self.offset_length:
            flags |= (self.offset_length << 2) & FRAME_FLAG_STREAM_DATA_OFFSET_LENGTH

        flags |= (self.id_length - 1) & FRAME_FLAG_STREAM_ID_LENGTH

        # Order does not matter, we are packing 1 byte
        return struct.pack('B', flags)



class ChloMsg():


    def __init__(self):
        self.msg_tag = b'CHLO'
        self.k_v = OrderedDict()


    def to_bytes(self):
        # MSG_TAG + K_V_COUNT + 2*0x00 bytes (PAD) + [tag: offset] + [tag_values]
        return bytearray([]).join(x for x in [self.msg_tag, struct.pack('<H', len(self.k_v)), b'\x00\x00' + self.serialize_keys() + self.serialize_values() ])


    def serialize_keys(self):
        buff = b''
        value_offset = 0

        for k, v in self.k_v.items():
            if verbose:
                print 'packing %s' % k
            #prepare key for network transmission
            if type(k) == str:
                int_k = int(binascii.hexlify(k[::-1]), 16)
            elif type(k) == int:
                int_k = k
            else:
                print 'unknown type'
                int_k = None
            if verbose:
                print int_k
            value_offset += len(v)
            buff += struct.pack('<I', int_k) + struct.pack('<I', value_offset)

        if verbose:
            print 'serialized keys'
            print binascii.hexlify(buff)

        return buff


    def serialize_values(self):
        buff = b''

        for item in self.k_v.values():
            if verbose:
                print 'serializing %s %d' % (item, len(item))
            if type(item) == bytearray:
                buff += item
            elif type(item) == str:
                tmp = bytearray()
                tmp.extend(item)
                buff += tmp
            else:
                print "Unkown type %s" % type(item)

        if verbose:
            print 'serialized_values'
            print buff
            print len(buff)

        return buff


def craft_QUIC_packet(con_id= -1):
    if con_id == -1:
        con_id = random.randint(0, 0xffffffffffffffff)

    # con_id_bytes = struct.pack(">Q", con_id)

    chlo = ChloMsg()

    #It's Glasgow uni afterall, make padding printable G
    chlo.k_v['PAD'] = b'\x47' * 1000
    chlo.k_v['VER'] = 'Q036'
    chlo.k_v['PDMD'] = 'X509'

    chlo_bytes = chlo.to_bytes()

    #Type, has_data_length, data_length, ID
    stream_hdr = StreamHdr(1, True, len(chlo_bytes), 1)
    stream_hdr_bytes = stream_hdr.to_bytes()

    pub_hdr = PublicHeader(con_id)
    pub_hdr_bytes = pub_hdr.to_bytes()

    pad = '\x00' * (1300 - (len(pub_hdr_bytes) + 12  + len(stream_hdr_bytes) + len(chlo_bytes) ) )
    magic_hash_bytes = '\x00' * 12

    payload = pub_hdr_bytes + magic_hash_bytes + stream_hdr_bytes + chlo_bytes + pad

    return (payload, con_id)