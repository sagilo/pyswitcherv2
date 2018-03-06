import socket
import struct
import time
import binascii
import argparse
import sys

g_switcher_ip = "1.1.1.1" # Change IP Address to your switcher IP
g_phone_id = "xxxx" # (uid) - 4 HEX digits
g_device_id = "xxxxxx" # (did) - 6 HEX digits 
g_device_pass = "yyyyyyyy" # 8 DEC digits

# don't touch from this point below

g_port = 9957
g_header_size_bytes = 40

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

def validate_header(header):
	length = len(header)
	assert length >= g_header_size_bytes, "Header must be at least %d bytes, current: %d" % (g_header_size_bytes, length)
	assert unpack(header[0:1]) == -2, "Expected -2 got %d" % unpack(header[0:1])
	assert unpack(header[1:2]) == -16, "Expected -16 got %d" % unpack(header[1:2])
	# 2:4 length
	assert unpack(header[4:5]) == 2, "Expected 2 got %d" % unpack(header[4:5])
	assert unpack(header[5:6]) == 50, "Expected 50 got %d" % unpack(header[5:6])
	# 6:8 command
	# 8:12 session
	# 12:14 serial
	# 14:15 dirt
	assert unpack(header[15:16]) == 0, "Expected 0 got %d" % unpack(header[15:16]) # error field, should be 0 on request
	assert unpack(header[16:18]) == 0, "Expected 0 got %d" % unpack(header[16:18])
	# 18:24 mac
	# 24:28 timestamp
	assert unpack(header[28:32]) == 0, "Expected 0 got %d" % unpack(header[28:32])
	assert unpack(header[32:36]) == 0, "Expected 0 got %d" % unpack(header[32:36])
	assert unpack(header[36:38]) == 0, "Expected 0 got %d" % unpack(header[36:38])
	assert unpack(header[38:39]) == -16, "Expected -16 got %d" % unpack(header[38:39])
	assert unpack(header[39:40]) == -2, "Expected -2 got %d" % unpack(header[39:40])

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
	header[2:4] = pack(length, 2) # struct.pack('<H', length) 
	header[6:8] = pack(command, 2) # struct.pack('<H', command)
	header[8:12] = pack(session, 4) # struct.pack('<I', session)
	header[12:14] = pack(serial, 2) # struct.pack('<H', serial)
	header[14:15] = pack(dirty, 1) # struct.pack('<b', dirty)
	#print ("\tMAC: %s" % binascii.hexlify(header[18:24]))
	header[24:28] = pack(timestamp, 4) # struct.pack('<I', int(round(time.time())))
	validate_header(header)

def get_command_from_header(header):
	return struct.unpack('<H', header[6:8])[0]

##########################################################################################
# local sign in 
##########################################################################################

def update_local_sign_in_body(data):
	data[40:42] = binascii.unhexlify("1c00")
	data[42:46] = binascii.unhexlify(g_phone_id)
	data[46:50] = binascii.unhexlify(g_device_pass)
	data[80:82] = pack(0, 2)

def generate_local_sign_in_request():
	length = 82
	command = 161
	data = bytearray(b'\x00') * (length - 4)
	session = 0
	update_request_header(data, length, command, session)
	assert get_command_from_header(data) == command, "This is not a local sign in request, not continuouing!, command: %d" % get_command_from_header(data)
	update_local_sign_in_body(data)
	data = calc_crc(data)
	
	print("Generated local sign in request, length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def send_local_sign_in(socket, logFile = None):
	request = generate_local_sign_in_request()
	print("Sending local sign in request")
	if logFile:
		logFile.write("Sending local sign in request: %s\n" % (binascii.hexlify(request)))

	session, response = send_packet_get_response(request, socket, logFile)
	print("Got local sign in response")
	if logFile:
		logFile.write("Got local sign in response, turned: %s, delay min: %d\n\t%d\n" % (isOn, delayMin, session))

	return session

##########################################################################################
# phone state
##########################################################################################

def update_phone_state_body(data):
	data[40:43] = binascii.unhexlify(g_device_id)

def generate_phone_state_request(session):
	length = 48
	command = 769
	data = bytearray(b'\x00') * (length - 4)
	update_request_header(data, length, command, session)
	assert get_command_from_header(data) == command, "This is not a phone state request, not continuouing!, command: %d" % get_command_from_header(data)

	update_phone_state_body(data)
	data = calc_crc(data)
	
	print("Generated phone state request, length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def send_phone_state(session, socket, logFile = None):
	request = generate_phone_state_request(session)
	print("Sending phone state request")
	if logFile:
		logFile.write("Sending phone state request: %s\n" % (binascii.hexlify(request)))

	session, response = send_packet_get_response(request, socket, logFile)
	print("Got control response")
	if logFile:
		logFile.write("Got phone state response, session: %d" % (session))

	print("response: %s" % binascii.hexlify(response))
	print("Device name: %s" % response[40:64])
	isOn = unpack(response[75:77])
	print("Is on? %d" % isOn)
	untilCloseSeconds = unpack(response[89:93])
	print("Seconds until close: %d seconds (%d minutes)" % (untilCloseSeconds, untilCloseSeconds/ 60))
	timeOpenSeconds = unpack(response[93:97])
	print("Time open seconds: %d seconds (%d minutes)" % (timeOpenSeconds, timeOpenSeconds / 60))

	return isOn == 1

##########################################################################################
# control (on/off)
##########################################################################################

def update_control_body(data, isOn, delayMin):
	print("Setting did (device id): %s" % g_device_id)
	data[40:43] = binascii.unhexlify(g_device_id)
	print("Setting uid (phone id): %s" % g_phone_id)
	data[44:48] = binascii.unhexlify(g_phone_id)
	print("Setting device_pass: %s" % g_device_pass)
	data[48:52] = binascii.unhexlify(g_device_pass)

	data[80:81] = pack(1, 1) # struct.pack('<b', 1) 
	data[81:83] = pack(6, 1) # struct.pack('<h', 6) # TODO constant ? 
	assert unpack(data[80:81]) == 1, "expected 1, got %d" % unpack(data[80:81])
	assert unpack(data[81:83]) == 6, "expected 6, got %d" % unpack(data[81:83])
	data[83:84] = pack(isOn, 1) # struct.pack('<b', isOn)
	assert unpack(data[84:85]) == 0, "expected 0, got %d" % unpack(data[84:85])
	data[85:89] = pack(delayMin * 60, 4) # struct.pack('<i', delayMin * 60)

def genereate_control_request(isOn, delayMin, session):
	length = 93
	command = 513
	data = bytearray(b'\x00') * (length - 4)
	update_request_header(data, length, command, session)
	assert get_command_from_header(data) == command, "This is not a control request, not continuouing!, command: %d" % get_command_from_header(data)

	update_control_body(data, isOn, delayMin)
	data = calc_crc(data)
	
	print("Generated control request. length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def send_control(isOn, delayMin, session, socket, logFile = None):
	request = genereate_control_request(isOn, delayMin, session)
	print("Sending control request, isOn: %d, delay: %d, request: \n\t%s" % (isOn, delayMin, binascii.hexlify(request)))
	if logFile:
		logFile.write("Sending control request, turning: %s, delay min: %d\n\t%s\n" % (isOn, delayMin, binascii.hexlify(request)))

	session, response = send_packet_get_response(request, socket, logFile)
	print("Got control response, session: %d" % session)
	if logFile:
		logFile.write("Got control response, turned: %s, delay min: %d" % (isOn, delayMin))

##########################################################################################
# crc
##########################################################################################

def calc_crc(data, key = "00000000000000000000000000000000"): 
	crc = bytearray(struct.pack('>I', binascii.crc_hqx(data, 4129)))
	data = data + crc[3:4] + crc[2:3]
	crc = crc[3:4] + crc[2:3] + bytearray(key)
	crc = bytearray(struct.pack('>I', binascii.crc_hqx(crc, 4129)))
	data = data + crc[3:4] + crc[2:3]
	return bytearray(data)

##########################################################################################
# parsing
##########################################################################################

def parse_pcap_file(file_path):
	from pcapfile import savefile

	print("Loading and parsing pcap file:")
	testcap = open(file_path, 'rb')
	capfile = savefile.load_savefile(testcap, layers=1, verbose=True)
	print("\n")
	for packet in capfile.packets:
		packet = bytearray(binascii.unhexlify(packet.packet.payload))
		if (len(packet) <= 40): # tcp header
			continue

		packet = packet[40:] # tcp header

		command = get_command_from_header(packet)
		if command != 513:
			#print("Not control command, continuouing to next packet, command: %d" % command)
			continue

		device_id = binascii.hexlify(packet[40:43])
		phone_id = binascii.hexlify(packet[44:46])
		device_pass = binascii.hexlify(packet[48:52])

		return device_id, phone_id, device_pass

	print("Didn't find ids in pcap file")
	sys.exit()

##########################################################################################
# socket helpers
##########################################################################################

def get_data_from_response_header(header):
	length = unpack(header[2:4])
	session = unpack(header[8:12])
	return session, (length - g_header_size_bytes)

def recv_response(socket):
	responseHeader = bytearray(socket.recv(g_header_size_bytes))
	assert len(responseHeader) >= g_header_size_bytes, "Respone header can't be smaller than %d bytes, got %d bytes, exiting" % (g_header_size_bytes, len(responseHeader))
	respSession, lengthLeft = get_data_from_response_header(responseHeader)
	responseBody = socket.recv(lengthLeft)
	return respSession, bytearray(responseHeader) + bytearray(responseBody)

def send_packet_get_response(request, socket, logFile = None):
	socket.send(request)
	session, response = recv_response(socket)
	assert session != 0, "Got session 0 in response"
	return session, response

def open_socket():
	print ("Openning socket")
	clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientsocket.connect((g_switcher_ip, g_port))
	print("Socket connected to %s:%d" % (g_switcher_ip, g_port))

	return clientsocket

def get_state():
	socket = open_socket()
	session = send_local_sign_in(socket)
	isOn = send_phone_state(session, socket)
	return 1 if isOn else 0

def control(on, timeMin):
	socket = open_socket()
	session = send_local_sign_in(socket)
	isOn = send_phone_state(session, socket)
	onSign = 1 if on else 0
	send_control(onSign , timeMin, session, socket)

def parse(file_path):
	device_id, phone_id, device_pass = parse_pcap_file(file_path)
	print("Device ID (did): %s" % device_id)
	print("Phone ID (uid): %s" % phone_id)
	print("Device pass: %s" % device_pass)

def parse_args():
	parser = argparse.ArgumentParser(description='Help me')
	modeChoices = ["on", "off", "get_state", "parse_pcap_file"]
	parser.add_argument('-m','--mode', dest='mode', choices=modeChoices, required=True)
	parser.add_argument('-t','--time', dest='timeMin', default=0, type=int, required=False)
	parser.add_argument('-f','--file_path', dest='file', help="Pcap file to parse (requires pypcapfile package)", required=False)

	args = vars(parser.parse_args())
	mode = args['mode']

	if mode == 'parse_pcap_file':
		assert 'file' in args, "No file given for parsing"

	return args

args = parse_args()
mode = args['mode']
if mode == 'get_state':
	rc = get_state()
	sys.exit(rc)
elif mode == 'parse_pcap_file':
	parse(args['file'])
elif mode == 'on' or mode == 'off':
	control(mode == 'on', args['timeMin'])
else:
	assert False, "Unexpected mode"
