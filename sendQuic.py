import socket
import struct
import sys
import random
import binascii
import os
import pprint
import select
import multiprocessing
import threading
import time

from quicPacket import QuicPacket


icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')
BASE_PORT = 6030



verbose = False

target = 1182952

fraction = int(target / 20)
progress = 0
percent = 0

timeout = .4

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



counter_lock = threading.Lock()
counter = 0

def parallel_controlled(dispatch_state, num_threads=20):
    write_log = Queue.Queue()

    ips = Queue.Queue()
    with open(probe_root + '/servers_feb') as ip_list:
        for line in ip_list:
            ips.put(line.strip())

    # Create sockets for each TTL <-> port mapping

    udp_sockets = []
    base_port = BASE_PORT
    for i in range(20):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.setblocking(0)

            try:
                udp_socket.bind(('', base_port + i + 1))
            except socket.error as e:
                if e.errno == 98:
                    # Handle case where port is taken
                    print "Port %d is taken" % (base_port + i + 1)

            udp_sockets.append(udp_socket)
        except Exception as e:
            print repr(e)
            print 'could not create socket series'

    t = Thread(target=vn_recvr, args=(udp_sockets, dispatch_state))
    t.setDaemon(True)
    t.start()

    #DEBUG
    global target
    target = 1000
    min_ips = Queue.Queue()
    for _ in range(target):
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

    print 'All workers finished'

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


# Probes server given by input parameter



def test_reachability(dest, udp_sockets, icmp_socket, quic_socket, fds):
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

    fds[dest_addr] = (icmp_socket, quic_socket)
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
        pre_send_time = time.time()
        udp_socket = udp_sockets[ttl-1]
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 1)

        udp_socket.sendto(b_data, (dest_addr, port))

        readable, _, s_errs = select.select([quic_socket._reader, icmp_socket._reader], [], [], .4)

        if verbose:
            print "TTL: %d " % ttl,
      #  print '%d udp recvd: %s ICMP recvd: %s' % (len(readable), send_socket in readable, recv_socket in readable)
        

        if readable:
            if quic_socket._reader in readable:
                with open('debug', 'a+') as f:
                    f.write('reading QUIC response for %s %d\n' % (dest_addr, ttl))
                try:
                    data, (addr, _) = quic_socket.get(block=False)
                except:
                    print 'error'
                #readable, _, _ = select.select([udp_socket], [], [], 0)
                #print len(readable)
                with open('debug', 'a+') as f:
                    f.write('done reading QUIC response for %s %s\n' % (dest_addr, addr) )
                
                # Get a list of supported versions
                parsed_quic = parse_QUIC_response(data)

                if verbose:
                    print 'read UDP socket %s %s %s' % (parsed_quic, addr, dest_addr)
                result.update(parsed_quic)

            if icmp_socket._reader in readable:
                data, (addr, _) = icmp_socket.get(block=False)
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
        sleep_time = 1 / 4.0 - (time.time() - pre_send_time)
        # send at most 4 packets from one thread every one second
        if sleep_time > 0:
            time.sleep(sleep_time)

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

    port = struct.unpack('!H', recv_data[48:50])[0] # bits 48 and 49 correspond to sender port number

    result = "%s, ECN: %d" % (curr_addr, ecn)
    if extracted_ttl:
        result += " Extracted TTL: %d" % extracted_ttl

    result += " Extracted TTL from port %d" % (port - BASE_PORT) # base port

    return result


def parse_QUIC_response(data):

    result = {}
    
    # convert the bytestream to hex stream
    hex_data = binascii.hexlify(data)

    # skip first 9 bytes (1 byte public flags + 8 bytes connection ID)
    versions = hex_data[18:]

    versions_decoded = QuicPacket.decode_versions(versions)
    result['versions'] = versions_decoded

    return result

def send_Q(ips, write_log, udp_sockets, dispatch_state):
    dest = None

    #Create a 'fake' socket to receive ICMP packets on
    icmp_receiver = multiprocessing.Queue()
    quic_receiver = multiprocessing.Queue()

    try:
        while True:
            try:
                if verbose:
                    print 'QSIZE: %d' % ips.qsize()
                dest = ips.get_nowait()
                print '%.2f %% completed' % ((target - ips.qsize()) / float(target) * 100)
                if verbose:
                    print 'Got %s' % dest
            except Queue.Empty:
                # We cannot pull a new ip, all have been assigned
                    if verbose:
                        print 'Thread finished %d ' % threading.current_thread().ident
                    return
            # Register ip with the ICMP receiver
            dispatch_state[dest] = (icmp_receiver, quic_receiver)

            if verbose:
                print 'processing %s' % dest
            result = test_reachability(dest, udp_sockets, icmp_receiver, quic_receiver, dispatch_state)
            if verbose:
                print 'Done %s' % dest

            if verbose:
                print 'reachability result:'
                pprint.pprint(result)

            # Remove ip from dispatcher state, all work has been processed
            del dispatch_state[dest]

            if verbose:
                print 'sending to logger'

            #Send result to be written
            write_log.put(repr(result))
            #print write_log.qsize()
    except Exception as e:
        if verbose:
            print repr(e)
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

            try:
                if dst_ip not in fds:
                    # this is a stale record, just ignore it
                    continue
                fds[dst_ip][0].put(icmp_data)
            except KeyError as e:
                # we've received a reply for a thread that is no longer operated on
                print 'key error'                
                print fds.keys()
                print dst_ip

            if verbose:
                print 'read ICMP'

def vn_recvr(udp_sockets, fds):
    while True:
        readable, _, _ = select.select(udp_sockets, [], [])
        if readable:
            for socket in udp_sockets:
                if socket in readable:
                    print 'read QUIC VN'
                    try:
                        data = socket.recvfrom(1024)
                        addr = data[1][0]
                        fds[addr][1].put(data)
                    except:
                        #TODO: decide how to handle this case
                        print '++++++++++++++++++error late QUIC received for %s ' % addr


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

    fds = {}
    t = Thread(target=icmp_recvr, args=(icmp_socket, fds))
    t.setDaemon(True)
    t.start()

    parallel_controlled(fds, 10)
    sys.exit(1)

    if any('single' in x for x in sys.argv):
        sendProbe(sys.argv[1])
    else:
        dest_name = sys.argv[1] if len(sys.argv) > 1 else ''
        main(dest_name)

