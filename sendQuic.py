import socket
import struct
import sys
import random
import binascii
import sys
import os
import pprint
import select
import multiprocessing


icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')


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
    l = [random.randint(17, 255) for _ in range(8)]
    # for x in l:
    #     print x
    #     print hex(x)

    # res = bytearray(l)

    # hex_res = binascii.hexlify(res)

    # hex_ints = [int(hex_res[i: i+2], 16) for i in range(0, len(hex_res), 2)]

    # print hex_ints
    
    # print bytearray(l) == bytearray(hex_ints)
    return bytearray(l)


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

def sendProbe(udp_socket, icmp_socket, fds, dest=''):
    # addr = 216.58.207.35
    # port = 443
    # SNI: google.com

    # try:
    result = test_reachability(dest, udp_socket, icmp_socket, fds)

    if verbose:
        print 'reachability result:'
        pprint.pprint(result)
    sys.exit(1)

    with open(probe_root + '/res/%s.res' % dest, 'w') as f:
        f.write( repr(result) + '\n')

    if verbose:
        print repr(result)

    if verbose:
        print 'Done'
    # except Exception as e:
    #     raise e
    #     with open(probe_root + '/errors/%s.err' % dest.strip(), 'w') as f:
    #         f.write(repr(e) + '\n')



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



from threading import Thread, Event
import Queue

def parallel_controlled(dispatch_state, num_threads=20):
    write_log = Queue.Queue()

    ips = Queue.Queue()
    with open(probe_root + '/servers_feb') as ip_list:
        for line in ip_list:
            ips.put(line.strip())

    # Create sockets for each TTL <-> port mapping

    udp_sockets = []
    base_port = 6030
    for i in range(20):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            try:
                udp_socket.bind(('', base_port + i + 1))
            except socket.error as e:
                if e.errno == 98:
                    # Handle case where port is taken
                    print "Port %d is taken" % base_port + i + 1

            udp_sockets.append(udp_socket)
        except Exception as e:
            print 'could not create socket series'

    #DEBUG
    min_ips = Queue.Queue()
    for _ in range(1):
        min_ips.put(ips.get())

    ips = min_ips
    #DEBUG

    threads = []
    print ips.qsize()
    for _ in range(num_threads):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except Exception as e:
            print 'could not create socket'
            raise e
            send_Q(ips, write_log)
            ips.put(dest)
            return

        t = Thread(target=send_Q, args=(ips, write_log, udp_sockets, dispatch_state))
        t.start()
        threads.append(t)

    stopWriting = Event()
    writer = Thread(target=logger, args=(write_log, stopWriting))
    writer.start()

    for t in threads:
        t.join()
    
    #print 'setting stop'
    stopWriting.set()
    writer.join()
    #print write_log.qsize()
    #All Ips have been processed, trigger event


def logger(write_log, stopWriting):
    with open(probe_root + '/script_combined', 'w') as out_log:
        has_items = True
        while not stopWriting.isSet() or has_items:
            try:
                entry = write_log.get(timeout=10)
                has_items = True
                #print 'writing'
                out_log.write(entry + '\n')
            except Queue.Empty:
                has_items = False
            
        print 'exiting now %s %s ' % (stopWriting.isSet(), has_items)


def generate_QUIC_packet(con_id = -1):
    flags = gen_public_flags()
    if con_id == -1:
        con_id = gen_con_id()
    else:
        con_id_hex = hex(con_id)[2:]
        # Sometimes the con_id number is of type 'long'
        if con_id_hex.endswith('L'):
            con_id_hex = con_id_hex[:-1]
        con_id = [int(con_id_hex[i: i+2], 16) for i in range(0, len(con_id_hex), 2)]
        con_id = bytearray(con_id)
    ver = gen_version_bytes()
    packet_no = gen_packet_number()

    stream_hdr = gen_stream_frame_hdr()
    
    chlo_content = gen_client_hello_data()

    forged_payload = forgePayload()    

    result = bytearray([]).join(x for x in [flags, con_id, ver, packet_no, forged_payload]) #, stream_hdr, chlo_content])

    return (result, con_id)


# Probes server given by input parameter

timeout = .4

def test_reachability(dest, udp_sockets, icmp_socket, fds):
    """Probes server given as input
    
    Arguments:
        dest  -- ip or Domain name of the server to be tested
        udp_socket -- fds to use for sending/receiving QUIC packets, based on TTL value
        icmp_socket -- fd to use for receiving ICMP packets
    Returns:
        result -- dict containing information about address, trace and supported versions, or error if probe timed out
    """
    (payload, con_id_base) = generate_QUIC_packet()

    if verbose:
        print "CON_ID %s" % binascii.hexlify(con_id_base)
    con_id_base = int(binascii.hexlify(con_id_base), 16)

    # con_id = con_id_base
    

    if verbose:
        print 'Payload:',
        print binascii.hexlify(payload)

    # 216.58.207.35 - google
    # 104.89.124.214 - akamai

    ip = '216.58.207.35'    

    #if dest:
        # if working with domain names we need to use: socket.gethostbyname(dest)
        
    dest_addr =  dest if dest else ip

    fds[dest_addr] = icmp_socket
    # dest_addr = '8.8.8.8'

    trace = {}
    result = {'address': dest_addr, 'trace': trace}

    port = 443
    max_hops = 20
    ttl = 1
    curr_addr = None

    b_data = payload

    timeouts = 0
    dest_reached = False
    while ttl < max_hops and not dest_reached:
        udp_socket = udp_sockets[ttl-1]
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 1)
        udp_socket.sendto(b_data, (dest_addr, port))
        
        readable, _, _ = select.select([udp_socket, icmp_socket._reader], [], [], timeout)

        if verbose:
            print "TTL: %d " % ttl,
      #  print '%d udp recvd: %s ICMP recvd: %s' % (len(readable), send_socket in readable, recv_socket in readable)
        
        if readable:
            if udp_socket in readable:
                data, (addr, _) = udp_socket.recvfrom(1024)
                
                # Get a list of supported versions
                parsed_quic = parse_QUIC_response(data)

                if verbose:
                    print 'read UDP socket %s %s %s' % (parsed_quic, addr, dest_addr)
                result.update(parsed_quic)

            if icmp_socket._reader in readable:
                data, (addr, _) = icmp_socket.get(block=False)
                port = struct.unpack('!H', data[48:50])[0] # bits 48 and 49 correspond to sender port number
                print "port %d" % port
                # sys.exit(1)
                dst_ip_bytes = binascii.hexlify(data)[88:96]
                dst_ip = '.'.join(str(int(dst_ip_bytes[x:x+2], 16)) for x in range(0, len(dst_ip_bytes), 2) )

                if verbose:
                    print 'Thread %s reading packet for %s' % (dest_addr, dst_ip)

                # Return extracted ECN
                parsed_icmp = parse_ICMP_response(data, addr, con_id_base)
                trace_record = result['trace'].get(ttl, '')
                trace_record += parsed_icmp
                result['trace'][ttl] = trace_record
                if verbose:
                    print 'reading ICMP socket %s' % repr(parsed_icmp)

            if addr == dest_addr:
                dest_reached = True
            ttl += 1
            timeouts = 0
        else:
            if verbose:
                print 'TO ',
            # Record timeout in trace    
            ttl_record = result['trace'].get(ttl, '')
            ttl_record += '* '

            result['trace'][ttl] = ttl_record
            timeouts += 1
            if timeouts == 3:
                ttl += 1
                if verbose:
                    print
                timeouts = 0

        (b_data, pre_send_con_id) = generate_QUIC_packet(con_id=con_id_base + ttl)
        if verbose:
            print 'con_ID pre-send: %d, %d, %s' % (int(binascii.hexlify(pre_send_con_id), 16), con_id_base, binascii.hexlify(pre_send_con_id))
    
    if ttl == max_hops:
        if 'versions' in result:
            result['error'] = 'Dual versions detected'
        else:
            result['versions'] = []
            result['error'] = 'Timeout'

    #Close Sockets
    #udp_socket.close()

    return result

NO_CON_ID = 1

def parse_ICMP_response(recv_data, curr_addr, base_con_id):
    result = ""

    print "RD %s" % type(recv_data)

    # Split the header and the data
    if verbose:
        print 'ICMP DATA: %s' % binascii.hexlify(recv_data)
    
    icmp_hdr = recv_data[20:28]
    
    icmp_pl = recv_data[28] + recv_data[29]
    t, code, checksum, _ = struct.unpack('bbHI', icmp_hdr)
    ver, ecn = struct.unpack('BB', icmp_pl)
#		sys.stdout.write("type: %s code: %s checksum: %s \n" % (t, code, checksum))
    ecn = ecn & 0b00000011 # get the last two bits of ToS field to extract ECN

    if verbose:
        print ("ecn: %d " % ecn)

    # Check if we have enough of the original packet to extract TTL
    extracted_ttl = None
    if len(recv_data) > 56:
        con_id = recv_data[57:65] # bytearray
        
        if verbose:
            print type(con_id)
            print binascii.hexlify(con_id)
        
        con_id = struct.unpack('!Q', con_id)[0] # long

        extracted_ttl = con_id - base_con_id
        if verbose:
            print 'conid as long: %d ' %  con_id
            print "extracted TTL: %d" % (con_id - base_con_id)
    else:
        global NO_CON_ID
        if verbose:
            print "ICMP payload too short, cannot extract conn_id %d" % NO_CON_ID
        NO_CON_ID += 1

    result = "%s, ECN: %d" % (curr_addr, ecn)
    if extracted_ttl:
        result += " Extracted TTL: %d" % extracted_ttl

    return result


def parse_QUIC_response(data):

    result = {}
    
    # convert the bytestream to hex stream
    hex_data = binascii.hexlify(data)

    # skip first 9 bytes (1 byte public flags + 8 bytes connection ID)
    versions = hex_data[18:]

    versions_decoded = decode_versions(versions)
    result['versions'] = versions_decoded

    return result


def send_Q(ips, write_log, udp_sockets, dispatch_state):
    dest = None

    #Create a 'fake' socket to receive ICMP packets on
    icmp_receiver = multiprocessing.Queue()

    try:
        while True:
            try:
                dest = ips.get_nowait()
            except Queue.Empty:
                # We cannot pull a new ip, all have been assigned
                return
            # Register ip with the ICMP receiver
            dispatch_state[dest] = icmp_receiver

            #TODO: Register current ip to 'icmp_socket' for dispatch state

            result = test_reachability(dest, udp_sockets, icmp_receiver, dispatch_state)

            if verbose:
                print 'reachability result:'
                pprint.pprint(result)

            # Remove ip from dispatcher state, all work has been processed
            del dispatch_state[dest]

            #Send result to be written
            write_log.put(repr(result))
            #print write_log.qsize()
    except Exception as e:
        # print type(e)
        #Anything that we could not detect, save to a file so we can debug later and not crash the script
        if not dest:
            dest = 'generic'
        with open(probe_root + '/errors_sec/%s.err' % dest.strip(), 'w') as f:
            f.write(repr(e) + '\n')

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

def icmp_recvr(icmp_socket, fds):
    while True:
        readable, _, _ = select.select([icmp_socket], [], [], timeout)
        if readable:
            icmp_data = icmp_socket.recvfrom(1024)

            dst_ip_bytes = binascii.hexlify(icmp_data[0])[88:96]
            dst_ip = '.'.join(str(int(dst_ip_bytes[x:x+2], 16)) for x in range(0, len(dst_ip_bytes), 2) )

            fds[dst_ip].put(icmp_data)
            if verbose:
                print 'read ICMP'

if __name__ == '__main__':

    probe_root = os.environ.get('PROBE_ROOT', '.')

    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except Exception as e:
        print 'could not create socket'
        raise e
        send_Q(ips, write_log)
        ips.put(dest)

    sudo_icmp = multiprocessing.Queue()
    fds = {}
    t = Thread(target=icmp_recvr, args=(icmp_socket, fds))
    t.setDaemon(True)
    t.start()

    # sendProbe(udp_socket, sudo_icmp, fds, dest='216.58.207.35')
    # sys.exit(1)
    # parallel()
    parallel_controlled(fds)
    sys.exit(1)

    if any('single' in x for x in sys.argv):
        sendProbe(sys.argv[1])
    else:
        dest_name = sys.argv[1] if len(sys.argv) > 1 else ''
        main(dest_name)

