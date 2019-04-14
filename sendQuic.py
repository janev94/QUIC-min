import socket
import struct
import sys
import random
import binascii
import sys
import os
#196e1da8b829ef3004513034330001b6229b973a57f818c50a04fc800143484c4f09000000504144008b030000534e490098030000564552009c03000043435300ac03000050444d44b00300004943534cb40300004d494453b803000043464357bc03000053464357c0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007777772e676f6f676c652e64650000000001e8816092921ae87eed8086a215829158353039050000006400000000c0000000800000



# First byte in QUIC packet is PUBLIC_FLAGS
# Public Flags:
# 0x01 = PUBLIC_FLAG_VERSION. Interpretation of this flag depends on whether the packet is sent by the server or the client. When sent by the client, setting it indicates that the header contains a QUIC Version (see below). This bit must be set by a client in all packets until confirmation from the server arrives agreeing to the proposed version is received by the client. A server indicates agreement on a version by sending packets without setting this bit. When this bit is set by the server, the packet is a Version Negotiation Packet. Version Negotiation is described in more detail later.
# 0x02 = PUBLIC_FLAG_RESET. Set to indicate that the packet is a Public Reset packet.
# 0x04 = Indicates the presence of a 32 byte diversification nonce in the header.
# 0x08 = Indicates the full 8 byte Connection ID is present in the packet. This must be set in all packets until negotiated to a different value for a given direction (e.g., client may request fewer bytes of the Connection ID be presented).  
# Two bits at 0x30 indicate the number of low-order-bytes of the packet number that are present in each packet. The bits are only used for Frame Packets. For Public Reset and Version Negotiation Packets (sent by the server) which don't have a packet number, these bits are not used and must be set to 0. Within this 2 bit mask:
# 0x30 indicates that 6 bytes of the packet number is present
# 0x20 indicates that 4 bytes of the packet number is present
# 0x10 indicates that 2 bytes of the packet number is present
# 0x00 indicates that 1 byte of the packet number is present
# 0x40 is reserved for multipath use.
# 0x80 is currently unused, and must be set to 0.

#
def gen_public_flags(version=1, pub_reset=0, divers_nonce=0, con_id=1, multipath=0):
    flags = '0b%s%s%s%s%s%s%s' % (0, multipath, '00', con_id, divers_nonce, pub_reset, version)
    return bytearray([int(flags, 2)])


def gen_con_id():
    return bytearray([random.randint(0, 255) for _ in range(8)])


def gen_version_bytes():
    return bytearray([ord(x) for x in 'Z036'])


def gen_packet_number():
    return bytearray([1])

####################################

def forgePayload():
    packet = '09215e9f6ef049a3265130333601063b3da74b109f33599b33c4a001140543484c4f0d000000504144004c040000564552005004000043435300600400004d5350436404000050444d44680400004943534c6c0400004354494d740400004e4f4e50940400004d4944539804000053434c539c040000435343549c04000043464357a004000053464357a40400002d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d5130333601e8816092921ae87eed8086a21582916400000058353039580200005263ab5c00000000550939ab3748d6a8bb21dc9f7be9c970ad21850c66825c0da56fdc8fd7ac521c640000000100000000400000004000000000000000000000000000000000000000000000'
    packet = packet[28:] # paylaod with computed hash
    
    #TODO: Remove
    #packet = alterhash(packet)


    payload = [int(packet[x:x+2], 16) for x in range(0, len(packet), 2)]
    return bytearray(payload)


def alterhash(packet):
    print 'toAlter'
    print packet[24:]

    #packet = packet[0] + '8' + packet[1:]
    packet = ''.join('0' for _ in range(24)) + packet[24:]
    return packet

def forgeP():
    content = []
#    with open('q_h') as f:
    for line in ['196e1da8b829ef3004513034330001b6229b973a57f818c50a04fc800143484c4f09000000504144008b030000534e490098030000564552009c03000043435300ac03000050444d44b00300004943534cb40300004d494453b803000043464357bc03000053464357c0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007777772e676f6f676c652e64650000000001e8816092921ae87eed8086a215829158353039050000006400000000c0000000800000', '']:
        content = [int(line[x:x+2], 16) for x in range(0, len(line) - 2, 2)]
        sys.stdout.write( str(len(content)) + '\n')   
        break 

    sys.stdout.write(str(content))
    return bytearray(content)


# MSB is always 1 to indicate this is STREAM frame
# fin = 1 bit
# data_len = 1 bit (yes/no)
# offset)len = 3 bits
# stream_length = 2 bits
def gen_stream_frame_hdr(has_fin=0, has_data_length=0, offset_length=0, stream_length=0):
    flags = "1%s%s%s%s" % (has_fin, has_data_length, bin(offset_length)[2:].zfill(3), bin(stream_length)[2:].zfill(2))
    return bytearray([int(flags, 2)])

# STREAM ID is always 1 (client hello)
# MSG TAG is CHLO
# Number of tags to be sent
# two bytes of padding
# A series of uint32 tags and uint32 end offsets, one for each tag-value pair
# The value data, concatenated without padding.

# Arguments:
#   tags -> a dictonary of the key/value pairs to be sent
def gen_client_hello_data(tags = {}):
    stream_id = [1]
    MSG_TAG = [ord(x) for x in "CHLO"]
    tags_num = [len(tags)]
    PAD = [0, 0]
    content = []
    
    payload = stream_id + MSG_TAG + tags_num + PAD + content
    return bytearray(payload)


# Every four bytes in the hex_str represent a version 
def decode_versions(hex_str):
    #TODO: Add support for non-gQUIC versions
    versions = [binascii.unhexlify(hex_str[i: i+8]) for i in range(0, len(hex_str), 8)]
    return versions


verbose = False

target = 1182952

fraction = int(target / 20)
progress = 0
percent = 0

def sendProbe(dest=''):
    # addr = 216.58.207.35
    # port = 443
    # SNI: google.com

    try:
        flags = gen_public_flags()
        con_id = gen_con_id()
        ver = gen_version_bytes()
        packet_no = gen_packet_number()

        stream_hdr = gen_stream_frame_hdr()
        
        chlo_content = gen_client_hello_data()

        forged_payload = forgePayload()    

        payload = bytearray([]).join(x for x in [flags, con_id, ver, packet_no, forged_payload]) #, stream_hdr, chlo_content])

        if verbose:
            print 'Pyauload:',
            print binascii.hexlify(payload)

        # 216.58.207.35 - google
        # 104.89.124.214 - akamai

        ip = '216.58.207.35'    

        #if dest:
            # if working with domain names we need to use: socket.gethostbyname(dest)
            
        dest_addr =  dest if dest else ip

        result = {'address': dest_addr}

        port = 443
        max_hops = 30
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')
        ttl = 1
        curr_addr = None

        b_data = payload

        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        # send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        # send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 1)
            
            
        # Set the receive timeout so we behave more like regular traceroute
        send_socket.settimeout(.4)

        timeouts = 0
        recvd = False
        while timeouts < 3 and not recvd:
            send_socket.sendto(b_data, (dest_addr, port))
            
            try:
                data = send_socket.recvfrom(1024)
                recvd = True
            except socket.timeout as e:
                # We have timed out, server did not return any QUIC versions
                timeouts += 1

        if recvd:
            if verbose:
                print 'received from: %s' % data[1][0]
            
            hex_data = binascii.hexlify(data[0])

            # skip first 9 bytes (1 byte public flags + 8 bytes connection ID)
            versions = binascii.hexlify(data[0])[18:]

            versions_decoded = decode_versions(versions)
            result['versions'] = versions_decoded
        else:
            result['error'] = 'timeout'
            result['versions'] = []

        with open(probe_root + '/res/%s.res' % dest, 'w') as f:
           f.write( repr(result) + '\n')

        if verbose:
            print repr(result)

        #Close Sockets
        send_socket.close()

        if verbose:
            print 'Done'
    except Exception as e:
       with open(probe_root + '/errors/%s.err' % dest.strip(), 'w') as f:
           f.write(repr(e) + '\n')


################################

from datetime import datetime
from multiprocessing.dummy import Pool
from multiprocessing import Process

def ipGenerator():
    with open(probe_root + '/servers_feb') as f:
        for line in f:
            yield line.strip()


def execProbe(servers):
    print "Starting at: ", str(datetime.now())
    pool = Pool()

    for i, _ in enumerate(pool.imap(sendProbe, servers), 1):
        print '\r' + str(datetime.now()) + ' ' + str((float(i)/chunk_size)*100) + '% done',

    pool.close()
    pool.join()
    print
    print 'Done'


num_proc = 4
chunk_size = 250

def parallel():
    num_proc = 32
    global chunk_size
    chunk_size = target / num_proc

    procs = []
    serverGenerator = ipGenerator()
    for _ in range(num_proc):
        servers = []
        while(len(servers) < chunk_size):
            servers += [serverGenerator.next()]
        p = Process(target=execProbe, args=(servers,))
        p.start()		
        procs.append(p)

    for p in procs:
			p.join()
		
    print "exec'd %d processes" % num_proc


#######################################



def main(dest_name=''):
    servers = []
    print 'generating servers'
    with open(probe_root + '/servers_feb') as f:
        for line in f:
            servers.append(line.strip())
    print 'done generating servers'
    #sys.stdout = open('probe_res', 'w')
    for server in servers:
        sendProbe(server)



if __name__ == '__main__':
    root = os.environ.get('PROBE_ROOT', '')
    probe_root = root if root else '.'
    parallel()
    sys.exit(1)

    if any('single' in x for x in sys.argv):
        sendProbe(sys.argv[1])
    else:
        dest_name = sys.argv[1] if len(sys.argv) > 1 else ''
        main(dest_name)

