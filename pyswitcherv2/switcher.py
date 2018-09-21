#!/usr/bin/env python

import socket
import struct
import time
import binascii
import argparse
import sys
import json
import os.path
import atexit

minKnownFirmwareVersionToWorkWith = "65.7"
maxKnownFirmwareVersionToWorkWith = "71.0"

g_def_credentials_filename = "credentials.json"

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

def get_command_from_header(header):
    return unpack(header[6:8])

class ValidationError(Exception):
    def __init__(self, message):
        super(ValidationError, self).__init__(message)

class ServerClosed(Exception):
    def __init__(self, message):
        super(ServerClosed, self).__init__(message)

class OutOfReach(Exception):
    def __init__(self, message):
        super(OutOfReach, self).__init__(message)

class Credentials():
    def __init__(self, phone_id, device_id, device_pass, switcher_ip = None):
        self._phone_id = phone_id
        self._device_id = device_id
        self._device_pass = device_pass
        self._switcher_ip = switcher_ip

    def __str__(self):
        return ("Phone ID: %s, Device ID: %s, Device Pass: %s, IP: %s" % (self._phone_id, self._device_id, self._device_pass, self._switcher_ip))

    def validate(self):
        if len(self._phone_id) != 4:
            raise ValidationError("Phone ID should be 4 digits long: '%s'" % self._phone_id)
        if not is_hex(self._phone_id):
            raise ValidationError("Phone ID should be hexadecimal digits: '%s'" % self._phone_id)

        if len(self._device_id) != 6:
            raise ValidationError("Device ID should be 6 digits long: '%s'" % self._phone_id)
        if not is_hex(self._device_id):
            raise ValidationError("Device ID should be hexadecimal digits: '%s'" % self._phone_id)

        if len(self._device_pass) != 8:
            raise ValidationError("Device Pass should be 8 digits long: '%s'" % self._phone_id)
        if not is_hex(self._device_pass):
            raise ValidationError("Device Pass should be hexadecimal digits: '%s'" % self._phone_id)

        if self._switcher_ip and self._switcher_ip == "1.1.1.1":
            raise ValidationError("Please update Switcher IP address in credentials file")

    def phone_id(self):
        return self._phone_id

    def device_id(self):
        return self._device_id

    def device_pass(self):
        return self._device_pass

    def switcher_ip(self):
        return self._switcher_ip if self._switcher_ip else "1.1.1.1"

class Switcher():
    __SOCKET_PORT = 9957
    __SOCKET_RECEIVE_BYTES = 1024
    __SOCKET_TIMEOUT_SEC = 15
    __MAX_RETRIES = 3

    def __init__(self, credentials, debug = False):
        self._credentials = credentials
        self._debug = debug
        self._socket = None
        atexit.register(self.cleanup)

    def __str__(self):
        return str(self._credentials)

    def cleanup(self):
        if self._socket:
            self._socket.close()
            self._socket = None

    def get_state(self):
        return self._get_state(1)

    def test_connection(self):
        return self._get_state(1)

    def _get_state(self, retry_num):
        try:
            self.__open_socket()
            session = self.__send_local_sign_in()
            is_on = self.__send_phone_state(session)
            print("Device is: %s" % ("on" if is_on else "off"))
            return is_on
        except ServerClosed as s:
            wait_seconds = retry_num * 3
            if self._debug and retry_num < self.__MAX_RETRIES:
                print("Server closed, retrying in %d seconds" % wait_seconds)
            elif retry_num >= self.__MAX_RETRIES:
                raise OutOfReach("Retries count maxed out, can't get state")

            time.sleep(wait_seconds)
            return self._get_state(retry_num + 1)

    def turn_on(self, time_minutes):
        return self._control(True, time_minutes, 1)

    def turn_off(self):
        return self._control(False, 0, 1)

    def _control(self, is_on, time_minutes, retry_num):
        try:
            self.__open_socket()
            session = self.__send_local_sign_in()
            self.__send_phone_state(session)
            self.__send_control(is_on , time_minutes, session)
            return 0
        except ServerClosed as s:
            wait_seconds = retry_num * 3
            if self._debug and retry_num < self.__MAX_RETRIES:
                print("Server closed, retrying in %d seconds" % wait_seconds)
            elif retry_num >= self.__MAX_RETRIES:
                raise OutOfReach("Retries count maxed out, can't control device")

            time.sleep(wait_seconds)
            self._control(False, 0, retry_num + 1)

    ##########################################################################################
    # socket helpers
    ##########################################################################################

    def __recv_response(self):
        HEADER_SIZE_BYTES = 40
        response = bytearray(self._socket.recv(self.__SOCKET_RECEIVE_BYTES))
        if len(response) < HEADER_SIZE_BYTES:
            raise ServerClosed("ERROR: failed getting response (server closed)")

        length = unpack(response[2:4])
        if self._debug:
            print("Response length (by response header): %d" % length)
        session = unpack(response[8:12])
        return session, response

    def __send_request_get_response(self, request):
        self._socket.send(request)
        return self.__recv_response()
        
    def __open_socket(self):
        if self._socket:
            self._socket.close()
            self._socket = None

        host = self._credentials.switcher_ip()
        port = self.__SOCKET_PORT
        timeout = self.__SOCKET_TIMEOUT_SEC

        try:
            print("Opening and connecting socket")
            self._socket = socket.create_connection((host, port), timeout = timeout)
            if self._debug:
                print("Socket connected to %s:%d" % (self._credentials.switcher_ip(), self.__SOCKET_PORT))
            else:
                print("Connected")
        except socket.timeout as t:
            raise OutOfReach("Connection timeout to %s, msg: %s" % (self._credentials.switcher_ip(), t))
        
    ##########################################################################################
    # reques header utils
    ##########################################################################################

    def __update_request_constants(self, header):
        header[0:1] = pack(-2, 1)
        header[1:2] = pack(-16, 1)
        header[4:5] = pack(2, 1)
        header[5:6] = pack(50, 1)
        header[38:39] = pack(-16, 1)
        header[39:40] = pack(-2, 1)

    def __update_request_header(self, header, length, command, session):
        self.__update_request_constants(header)
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

    ##########################################################################################
    # local sign in 
    ##########################################################################################

    def __update_local_sign_in_body(self, data):
        data[40:42] = binascii.unhexlify("1c00") # version
        data[42:46] = binascii.unhexlify(self._credentials.phone_id())
        data[46:50] = binascii.unhexlify(self._credentials.device_pass())
        data[76:78] = pack(0, 2)

    def __generate_local_sign_in_request(self):
        LOCAL_SIGN_IN_COMMAND = 161
        LOCAL_SIGN_IN_LENGTH = 82

        data = bytearray(LOCAL_SIGN_IN_LENGTH - 4)
        session = 0
        self.__update_request_header(data, LOCAL_SIGN_IN_LENGTH, LOCAL_SIGN_IN_COMMAND, session)
        assert get_command_from_header(data) == LOCAL_SIGN_IN_COMMAND, "This is not a local sign in request, not continuouing!, command: %d" % get_command_from_header(data)
        self.__update_local_sign_in_body(data)
        return self.__calc_crc(data)

    def __send_local_sign_in(self):
        request = self.__generate_local_sign_in_request()

        if self._debug:
            print("Sending local sign in request: \n\t%s" % binascii.hexlify(request))
        else:
            print("Sending local sign in request")

        session, response = self.__send_request_get_response(request)

        if self._debug:
            print("Got local sign in response, session: %d, response: \n\t%s\n" % (session, binascii.hexlify(response)))
        else:
            print("Got local sign in response, session: %d" % session)

        return session

    ##########################################################################################
    # phone state
    ##########################################################################################

    def __update_phone_state_body(self, data):
        data[40:43] = binascii.unhexlify(self._credentials.device_id())
        data[43:44] = pack(0, 1)

    def __generate_phone_state_request(self, session):    
        PHONE_STATE_COMMAND = 769
        PHONE_STATE_REQ_LENGTH = 48

        data = bytearray(PHONE_STATE_REQ_LENGTH - 4)
        self.__update_request_header(data, PHONE_STATE_REQ_LENGTH, PHONE_STATE_COMMAND, session)
        assert get_command_from_header(data) == PHONE_STATE_COMMAND, "This is not a phone state request, not continuouing!, command: %d" % get_command_from_header(data)

        self.__update_phone_state_body(data)
        data = self.__calc_crc(data)

        return data

    def __send_phone_state(self, session):
        request = self.__generate_phone_state_request(session)

        if self._debug:
            print("Sending phone state request: \n\t%s" % binascii.hexlify(request))
        else:
            print("Sending phone state request")

        session, response = self.__send_request_get_response(request)

        is_on = unpack(response[75:77])
        minutes_to_off = unpack(response[89:93]) / 60
        minutes_on = unpack(response[93:97]) / 60

        if self._debug:
            #print("Device name: %s" % response[40:64])
            print("Got phone state response, session: %d, on: %d, minutes to off: %d, minutes on: %d, response: \n\t%s\n" % (session, is_on, minutes_to_off, minutes_on, binascii.hexlify(response)))
        else:
            print("Got phone state response")

        return is_on == 1

    ##########################################################################################
    # control (on/off)
    ##########################################################################################

    def __update_control_body(self, data, is_on, time_min):
        data[40:43] = binascii.unhexlify(self._credentials.device_id())
        data[44:48] = binascii.unhexlify(self._credentials.phone_id())
        data[48:52] = binascii.unhexlify(self._credentials.device_pass())

        data[80:81] = pack(1, 1) 
        data[81:83] = pack(6, 1) # TODO constant ? 
        assert unpack(data[80:81]) == 1, "expected 1, got %d" % unpack(data[80:81])
        assert unpack(data[81:83]) == 6, "expected 6, got %d" % unpack(data[81:83])
        data[83:84] = pack(is_on, 1)
        assert unpack(data[84:85]) == 0, "expected 0, got %d" % unpack(data[84:85])
        data[85:89] = pack(time_min * 60, 4)

    def __genereate_control_request(self, is_on, time_minutes, session):        
        CONTROL_COMMAND = 513
        CONTROL_REQ_LENGTH = 93

        data = bytearray(CONTROL_REQ_LENGTH - 4)
        self.__update_request_header(data, CONTROL_REQ_LENGTH, CONTROL_COMMAND, session)
        assert get_command_from_header(data) == CONTROL_COMMAND, "This is not a control request, not continuouing!, command: %d" % get_command_from_header(data)
        self.__update_control_body(data, is_on, time_minutes)
        return self.__calc_crc(data)
        
    def __send_control(self, is_on, time_minutes, session):
        request = self.__genereate_control_request(is_on, time_minutes, session)

        if self._debug:
            print("Sending control request, is_on: %d, minutes: %d: \n\t%s" % (is_on, time_minutes, binascii.hexlify(request)))
        else:
            print("Sending control request, is_on: %d, minutes: %d" % (is_on, time_minutes))
        
        session, response = self.__send_request_get_response(request)

        if self._debug:
            print("Got control response, action: %s, minutes: %d, session: %d, response: \n\t%s\n" % (is_on, time_minutes, session, binascii.hexlify(response)))
        else:
            print("Got control response")


    ##########################################################################################
    # crc
    ##########################################################################################

    def __calc_crc(self, data, key = "00000000000000000000000000000000"): 
        crc = bytearray(struct.pack('>I', binascii.crc_hqx(data, 4129)))
        data = data + crc[3:4] + crc[2:3]
        crc = crc[3:4] + crc[2:3] + bytearray(key, 'utf8')
        crc = bytearray(struct.pack('>I', binascii.crc_hqx(crc, 4129)))
        data = data + crc[3:4] + crc[2:3]
        return bytearray(data)

##########################################################################################
# commander functions
##########################################################################################

def exit_with_error(msg):
    err_msg = "ERROR: %s" % msg
    print(err_msg)
    sys.exit(-1)

##########################################################################################
# parsing
##########################################################################################

def extract_credentials_from_pcap(pcap_file, is_debug):
    try:
        from pcapfile import savefile
    except ImportError as e:
        raise Exception("Missing 'pypcapfile' package, please install (pip install pypcapfile)")

    if is_debug:
        print("Loading and parsing pcap file: %s" % pcap_file)
    try:
        file = open(pcap_file, 'rb')
        capfile = savefile.load_savefile(file, layers=1, verbose=True)
        print("\n")
        for packet in capfile.packets:
            packet = bytearray(packet.packet.payload)
            if (len(packet) <= 40): # tcp header
                continue

            packet = packet[40:] # tcp header

            command = get_command_from_header(packet)
            if command != 513:
                if is_debug:
                    print("Not control command, continuing to next packet, command: %d" % command)
                continue

            phone_id = binascii.hexlify(packet[44:46]).decode("utf-8") 
            device_id = binascii.hexlify(packet[40:43]).decode("utf-8")
            device_pass = binascii.hexlify(packet[48:52]).decode("utf-8")
            
            credentials = Credentials(phone_id, device_id, device_pass)
            credentials.validate()
            return credentials

        exit_with_error("ERROR: Didn't find relevant ids in pcap file")
    except Exception as exception:
        raise Exception("Error pasing pcap file: %s" % exception)

##########################################################################################
# credentials
##########################################################################################

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def read_credentials(credentials_file):
    data = json.load(open(credentials_file))

    phone_id = data["phone_id"]
    device_id = data["device_id"] 
    device_pass = data["device_pass"]
    switcher_ip = data["ip"]

    credentials = Credentials(phone_id, device_id, device_pass, switcher_ip)
    credentials.validate()
    return credentials

def write_credentials(credentials, credentials_file):
    data = {}
    data["phone_id"] = credentials.phone_id()
    data["device_id"] = credentials.device_id()
    data["device_pass"] = credentials.device_pass()
    data["ip"] = credentials.switcher_ip()

    with open(credentials_file, 'w') as outfile:
         json.dump(data, outfile)

##########################################################################################
# modes
##########################################################################################

def parse_pcap_file(pcap_file, credentials_file, is_debug):
    credentials = extract_credentials_from_pcap(pcap_file, is_debug)
    print("Device ID (did): %s" % credentials.device_id())
    print("Phone ID (uid): %s" % credentials.phone_id())
    print("Device pass: %s" % credentials.device_pass())
    write_credentials(credentials, credentials_file)
    print("Wrote credential files successfully. Please update Switcher IP address (%s)" % credentials_file)

    return 0

def set_credentials(credentials, credentials_file):
    write_credentials(credentials, credentials_file)
    print("Updated credentials file successfully")

    return 0

##########################################################################################
# main
##########################################################################################

def parse_args():
    parser = argparse.ArgumentParser(description='Help me')
    mode_choices = ["on", "off", "get_state", "parse_pcap_file", "set_credentials"]
    parser.add_argument('-m','--mode', dest='mode', choices=mode_choices, required=True)
    parser.add_argument('-t','--time', dest='time_min', default=0, type=int, required=False)
    parser.add_argument('-f','--file_path', dest='pcap_file', help="Pcap file to parse (requires pypcapfile package)", required=False)
    parser.add_argument('-d','--debug', dest='debug', default=False, action='store_true', required=False)
    parser.add_argument('-c','--credentials_file_path', dest='credentials_file', help='Path to credentials file if not next to script', required=False)
    parser.add_argument('--device_id', dest='device_id', required=False, help="Device ID to set when using 'set_credentials' mode")
    parser.add_argument('--phone_id', dest='phone_id', required=False, help="Phone ID to set when using 'set_credentials' mode")
    parser.add_argument('--device_pass', dest='device_pass', required=False, help="Device pass to set when using 'set_credentials' mode")
    parser.add_argument('--switcher_ip', dest='switcher_ip', required=False, help="Switcher local ip to set when using 'set_credentials' mode")

    args = parser.parse_args()
    mode = args.mode
    if mode == 'parse_pcap_file':
        pcap_file = args.pcap_file
        if pcap_file == None:
            exit_with_error("No file given for parsing (-f)")
        elif not os.path.isfile(pcap_file):
            exit_with_error("Can't find pcap file: '%s'" % pcap_file)

    if mode == 'set_credentials':
        if not args.device_id:
            exit_with_error("Missing --device_id")
        if not args.phone_id:
            exit_with_error("Missing --phone_id")
        if not args.device_pass:
            exit_with_error("Missing --device_pass")
        if not args.switcher_ip:
            exit_with_error("Missing --switcher_ip")

    if args.credentials_file:
        if args.debug:
            print("Using credential file: '%s'" % args.credentials_file)
    else:
        args.credentials_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), g_def_credentials_filename)

    if mode == 'get_state' or mode == 'on' or mode == 'off':
        if not os.path.isfile(args.credentials_file):
            exit_with_error("Missing credentials file (%s), run script in 'parse pcap file' or 'set credentials' mode to generate file" % args.credentials_file)

    return args

def run(args):
    mode = args.mode

    if mode == 'parse_pcap_file':
        return parse_pcap_file(args.pcap_file, args.credentials_file, args.debug)
    elif mode == 'set_credentials':
        credentials = Credentials(args.phone_id, args.device_id, args.device_pass, args.switcher_ip)
        credentials.validate()
        return set_credentials(credentials, args.credentials_file)

    credentials = read_credentials(args.credentials_file)
    switcher = Switcher(credentials, args.debug)

    if mode == 'get_state': 
        is_on = switcher.get_state()
        return 0 if is_on else 1
    elif mode == 'on':
        return switcher.turn_on(args.time_min)
    elif mode == 'off':
         return switcher.turn_off()

    raise Exception("Unexpected mode (please report to developer): '%s'" % mode)
    
def get_timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

def main():
    args = parse_args()
    print("%s | mode: %s" % (get_timestamp(), args.mode))
    sys.exit(run(args))

if __name__ == '__main__': 
    main()