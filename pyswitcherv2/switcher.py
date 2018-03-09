#!/usr/bin/env python

import socket
import struct
import time
import binascii
import argparse
import sys
import json
import os.path

knownFirmwareVersionToWorkWith = "65.7"
knownAppVersionToWorkWith = "1.3"

g_credentials_filename = "credentials.json"
g_port = 9957
g_header_size_bytes = 40
g_debug = False
g_socket = None
g_receive_size = 1024
g_num_of_retries = 3

def exit_with_error(msg):
    print(msg)
    exit(-1)

def exit(code):
    if g_socket:
        print("Closing socket...")
        g_socket.close()
    sys.exit(code)

def unpack(bytes):
    size = len(bytes)
    fmt = '<'
    if size == 1:
        fmt += 'b'
    elif size == 2:
        fmt += 'H'
    elif size == 4:
        fmt += 'I'
    else:
        assert False, "Unexpected size: %d" % size
    return struct.unpack(fmt, bytes)[0]

def pack(integral, size):
    fmt = '<'
    if size == 1:
        fmt += 'b'
    elif size == 2:
        fmt += 'H'
    elif size == 4:
        fmt += 'I'
    else:
        assert False, "Unexpected size: %d" % size
    return struct.pack(fmt, integral)

def update_request_constants(header):
    header[0:1] = pack(-2, 1)
    header[1:2] = pack(-16, 1)
    header[4:5] = pack(2, 1)
    header[5:6] = pack(50, 1)
    header[38:39] = pack(-16, 1)
    header[39:40] = pack(-2, 1)

def update_request_header(header, length, command, session):
    update_request_constants(header)
    serial = 52
    dirty = 1
    timestamp = int(round(time.time()))
    header[2:4] = pack(length, 2) 
    header[6:8] = pack(command, 2)
    header[8:12] = pack(session, 4)
    header[12:14] = pack(serial, 2)
    header[14:15] = pack(dirty, 1)
    #header[18:26] = 0 # 6 bytes did, not required
    header[24:28] = pack(timestamp, 4)

def get_command_from_header(header):
    return unpack(header[6:8])

##########################################################################################
# local sign in 
##########################################################################################

LOCAL_SIGN_IN_COMMAND = 161
LOCAL_SIGN_IN_LENGTH = 82

def update_local_sign_in_body(data):
    data[40:42] = binascii.unhexlify("1c00") # version
    data[42:46] = binascii.unhexlify(g_phone_id)
    data[46:50] = binascii.unhexlify(g_device_pass)
    data[76:78] = pack(0, 2)

def generate_local_sign_in_request():
    data = bytearray(LOCAL_SIGN_IN_LENGTH - 4)
    session = 0
    update_request_header(data, LOCAL_SIGN_IN_LENGTH, LOCAL_SIGN_IN_COMMAND, session)
    assert get_command_from_header(data) == LOCAL_SIGN_IN_COMMAND, "This is not a local sign in request, not continuouing!, command: %d" % get_command_from_header(data)
    update_local_sign_in_body(data)
    return calc_crc(data)

def send_local_sign_in():
    request = generate_local_sign_in_request()

    if g_debug:
        print("Sending local sign in request: \n\t%s" % binascii.hexlify(request))
    else:
        print("Sending local sign in request")

    session, response = send_request_get_response(request)

    if g_debug:
        print("Got local sign in response, session: %d, response: \n\t%s\n" % (session, binascii.hexlify(response)))
    else:
        print("Got local sign in response")

    return session

##########################################################################################
# phone state
##########################################################################################

PHONE_STATE_COMMAND = 769
PHONE_STATE_REQ_LENGTH = 48

def update_phone_state_body(data):
    data[40:43] = binascii.unhexlify(g_device_id)
    data[43:44] = pack(0, 1)

def generate_phone_state_request(session):
    data = bytearray(PHONE_STATE_REQ_LENGTH - 4)
    update_request_header(data, PHONE_STATE_REQ_LENGTH, PHONE_STATE_COMMAND, session)
    assert get_command_from_header(data) == PHONE_STATE_COMMAND, "This is not a phone state request, not continuouing!, command: %d" % get_command_from_header(data)

    update_phone_state_body(data)
    data = calc_crc(data)
        
    return data

def send_phone_state(session):
    request = generate_phone_state_request(session)

    if g_debug:
        print("Sending phone state request: \n\t%s" % binascii.hexlify(request))
    else:
        print("Sending phone state request")

    session, response = send_request_get_response(request)

    is_on = unpack(response[75:77])
    minutes_to_off = unpack(response[89:93]) / 60
    minutes_on = unpack(response[93:97]) / 60

    if g_debug:
        #print("Device name: %s" % response[40:64])
        print("Got phone state response, session: %d, on: %d, minutes to off: %d, minutes on: %d, response: \n\t%s\n" % (session, is_on, minutes_to_off, minutes_on, binascii.hexlify(response)))
    else:
        print("Got phone state response")

    return is_on == 1

##########################################################################################
# control (on/off)
##########################################################################################

CONTROL_COMMAND = 513
CONTROL_REQ_LENGTH = 93

def update_control_body(data, is_on, time_min):
    data[40:43] = binascii.unhexlify(g_device_id)
    data[44:48] = binascii.unhexlify(g_phone_id)
    data[48:52] = binascii.unhexlify(g_device_pass)

    data[80:81] = pack(1, 1) 
    data[81:83] = pack(6, 1) # TODO constant ? 
    assert unpack(data[80:81]) == 1, "expected 1, got %d" % unpack(data[80:81])
    assert unpack(data[81:83]) == 6, "expected 6, got %d" % unpack(data[81:83])
    data[83:84] = pack(is_on, 1)
    assert unpack(data[84:85]) == 0, "expected 0, got %d" % unpack(data[84:85])
    data[85:89] = pack(time_min * 60, 4)

def genereate_control_request(is_on, time_min, session):
    data = bytearray(CONTROL_REQ_LENGTH - 4)
    update_request_header(data, CONTROL_REQ_LENGTH, CONTROL_COMMAND, session)
    assert get_command_from_header(data) == CONTROL_COMMAND, "This is not a control request, not continuouing!, command: %d" % get_command_from_header(data)
    update_control_body(data, is_on, time_min)
    return calc_crc(data)
    
def send_control(isOn, timeMin, session):
    request = genereate_control_request(isOn, timeMin, session)

    if g_debug:
        print("Sending control request, isOn: %d, minutes: %d: \n\t%s" % (isOn, timeMin, binascii.hexlify(request)))
    else:
        print("Sending control request, isOn: %d, minutes: %d" % (isOn, timeMin))
    
    session, response = send_request_get_response(request)

    if g_debug:
        print("Got control response, action: %s, minutes: %d, session: %d, response: \n\t%s\n" % (isOn, timeMin, session, binascii.hexlify(response)))
    else:
        print("Got control response")

##########################################################################################
# crc
##########################################################################################

def calc_crc(data, key = "00000000000000000000000000000000"): 
    crc = bytearray(struct.pack('>I', binascii.crc_hqx(data, 4129)))
    data = data + crc[3:4] + crc[2:3]
    crc = crc[3:4] + crc[2:3] + bytearray(key, 'utf8')
    crc = bytearray(struct.pack('>I', binascii.crc_hqx(crc, 4129)))
    data = data + crc[3:4] + crc[2:3]
    return bytearray(data)

##########################################################################################
# parsing
##########################################################################################

def extract_credentials_from_pcap(pcap_file):
    from pcapfile import savefile

    print("Loading and parsing pcap file:")
    testcap = open(pcap_file, 'rb')
    capfile = savefile.load_savefile(testcap, layers=1, verbose=True)
    print("\n")
    for packet in capfile.packets:
        packet = bytearray(binascii.unhexlify(packet.packet.payload))
        if (len(packet) <= 40): # tcp header
            continue

        packet = packet[40:] # tcp header

        command = get_command_from_header(packet)
        if command != 513:
            if g_debug:
                print("Not control command, continuing to next packet, command: %d" % command)
            continue

        device_id = binascii.hexlify(packet[40:43]).decode("utf-8") 
        phone_id = binascii.hexlify(packet[44:46]).decode("utf-8") 
        device_pass = binascii.hexlify(packet[48:52]).decode("utf-8")
        
        return device_id, phone_id, device_pass

    exit_with_error("ERROR: Didn't find ids in pcap file")

##########################################################################################
# socket helpers
##########################################################################################

def recv_response():
    response = bytearray(g_socket.recv(g_receive_size))
    if len(response) < g_header_size_bytes:
        print("ERROR: error getting response (server closed)")
        raise Exception("ERROR: error getting response (server closed)")

    length = unpack(response[2:4])
    if g_debug:
        print("Response length (by response header): %d" % length)
    session = unpack(response[8:12])
    return session, response

def send_request_get_response(request):
    g_socket.send(request)
    return recv_response()
    
def open_socket():
    global g_socket
    if g_socket:
        g_socket.close()

    print ("Connecting...")
    g_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    g_socket.connect((g_switcher_ip, g_port))
    if g_debug:
        print("Socket connected to %s:%d" % (g_switcher_ip, g_port))
    else:
        print("Connected")

def read_credentials(credentials_file):
    data = json.load(open(credentials_file))
    global g_switcher_ip
    global g_device_id
    global g_phone_id
    global g_device_pass

    g_switcher_ip = data["ip"]
    g_phone_id = data["phone_id"]
    g_device_id = data["device_id"] 
    g_device_pass = data["device_pass"]

    if g_switcher_ip == "1.1.1.1":
        exit_with_error("ERROR: Please update Switcher IP address in %s" % credentials_file)

def write_credentials(device_id, phone_id, device_pass):
    data = {}
    data["ip"] = "1.1.1.1"
    data["phone_id"] = phone_id
    data["device_id"] = device_id
    data["device_pass"] = device_pass

    with open(g_credentials_filename, 'w') as outfile:
         json.dump(data, outfile)

def get_state(credentials_file):
    read_credentials(credentials_file)
    open_socket()
    session = send_local_sign_in()
    is_on = send_phone_state(session)
    print("Device is: %s" % ("on" if is_on else "off"))
    return 0 if is_on else 1

def control(on, time_min, credentials_file):
    read_credentials(credentials_file)
    open_socket()
    session = send_local_sign_in()
    send_phone_state(session)
    send_control(on , time_min, session)

def parse_pcap_file(file_path):
    device_id, phone_id, device_pass = extract_credentials_from_pcap(file_path)
    print("Device ID (did): %s" % device_id)
    print("Phone ID (uid): %s" % phone_id)
    print("Device pass: %s" % device_pass)
    write_credentials(device_id, phone_id, device_pass)
    print("Wrote credential files successfully. Please update Switcher IP address (%s)" % g_credentials_filename)

def parse_args():
    parser = argparse.ArgumentParser(description='Help me')
    mode_choices = ["on", "off", "get_state", "parse_pcap_file"]
    parser.add_argument('-m','--mode', dest='mode', choices=mode_choices, required=True)
    parser.add_argument('-t','--time', dest='time_min', default=0, type=int, required=False)
    parser.add_argument('-f','--file_path', dest='pcap_file', help="Pcap file to parse (requires pypcapfile package)", required=False)
    parser.add_argument('-d','--debug', dest='debug', default=False, action='store_true', required=False)
    parser.add_argument('-c','--credentials_file_path', default=g_credentials_filename, dest='credentials_file', help='Path to credentials file if not next to script', required=False)

    args = parser.parse_args()
    global g_debug
    g_debug = args.debug
    mode = args.mode

    if mode == 'parse_pcap_file':
        pcap_file = args.pcap_file
        if pcap_file == None:
            exit_with_error("No file given for parsing (-f)")
        elif not os.path.isfile(pcap_file):
            exit_with_error("Can't find pcap file: '%s'" % pcap_file)

    if mode == 'get_state' or mode == 'on' or mode == 'off':
        credentials_file = args.credentials_file
        if not os.path.isfile(credentials_file):
            exit_with_error("ERROR: Missing credentials file (%s), run script in parse mode to generate from pcap file" % credentials_file)

    return args

def run(args, try_num):
    if try_num >= g_num_of_retries:
        exit_with_error("ERROR: Reached max num of retries (%d), exiting..." % g_num_of_retries)

    try:
    	mode = args.mode
        if mode == 'get_state': 
            return get_state(args.credentials_file)
        
        if mode == 'parse_pcap_file':
            parse_pcap_file(args.pcap_file)
        elif mode == 'on' or mode == 'off':
            control(mode == 'on', args.time_min, args.credentials_file)
        else:
            exit_with_error("ERROR: unexpected mode")

        return 0
    except Exception:
    	sleep_sec = 3 * try_num
        print("Retrying in %d seconds" % sleep_sec)
        time.sleep(sleep_sec)
        return run(args, try_num + 1)

args = parse_args()
print("%s") % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
exit(run(args, 1))
