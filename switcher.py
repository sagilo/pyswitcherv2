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

def validateHeader(header):
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

def updateHeaderConstants(header):
	header[0:1] = pack(-2, 1)
	header[1:2] = pack(-16, 1)
	header[4:5] = pack(2, 1)
	header[5:6] = pack(50, 1)
	header[38:39] = pack(-16, 1)
	header[39:40] = pack(-2, 1)

def updateRequestHeader(header, length, command, session):
	updateHeaderConstants(header)
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
	validateHeader(header)

def getCommandFromHeader(header):
	return struct.unpack('<H', header[6:8])[0]

##########################################################################################
# local sign in 
##########################################################################################

def updateLocalSignInBody(data):
	data[40:42] = binascii.unhexlify("1c00")
	data[42:46] = binascii.unhexlify(g_phone_id)
	data[46:50] = binascii.unhexlify(g_device_pass)
	data[80:82] = pack(0, 2)

def generateLocalSignInRequest():
	length = 82
	command = 161
	data = bytearray(b'\x00') * (length - 4)
	session = 0
	updateRequestHeader(data, length, command, session)
	assert getCommandFromHeader(data) == command, "This is not a local sign in request, not continuouing!, command: %d" % getCommandFromHeader(data)
	updateLocalSignInBody(data)
	data = calcCRC(data)
	
	print("Generated local sign in request, length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def sendLocalSignIn(socket, logFile = None):
	request = generateLocalSignInRequest()
	print("Sending local sign in request")
	if logFile:
		logFile.write("Sending local sign in request: %s\n" % (binascii.hexlify(request)))

	session, response = sendPacketGetResponse(request, socket, logFile)
	print("Got local sign in response")
	if logFile:
		logFile.write("Got local sign in response, turned: %s, delay min: %d\n\t%d\n" % (isOn, delayMin, session))

	return session

##########################################################################################
# phone state
##########################################################################################

def updatePhoneStateBody(data):
	data[40:43] = binascii.unhexlify(g_device_id)

def generatePhoneStateRequest(session):
	length = 48
	command = 769
	data = bytearray(b'\x00') * (length - 4)
	updateRequestHeader(data, length, command, session)
	assert getCommandFromHeader(data) == command, "This is not a phone state request, not continuouing!, command: %d" % getCommandFromHeader(data)

	updatePhoneStateBody(data)
	data = calcCRC(data)
	
	print("Generated phone state request, length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def sendPhoneState(session, socket, logFile = None):
	request = generatePhoneStateRequest(session)
	print("Sending phone state request")
	if logFile:
		logFile.write("Sending phone state request: %s\n" % (binascii.hexlify(request)))

	session, response = sendPacketGetResponse(request, socket, logFile)
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

def updateControlBody(data, isOn, delayMin):
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

def generateControlRequest(isOn, delayMin, session):
	length = 93
	command = 513
	data = bytearray(b'\x00') * (length - 4)
	updateRequestHeader(data, length, command, session)
	assert getCommandFromHeader(data) == command, "This is not a control request, not continuouing!, command: %d" % getCommandFromHeader(data)

	updateControlBody(data, isOn, delayMin)
	data = calcCRC(data)
	
	print("Generated control request. length: %d packet: \n\t%s" % (len(data), binascii.hexlify(data)))
	
	return data

def sendControl(isOn, delayMin, session, socket, logFile = None):
	request = generateControlRequest(isOn, delayMin, session)
	print("Sending control request, isOn: %d, delay: %d, request: \n\t%s" % (isOn, delayMin, binascii.hexlify(request)))
	if logFile:
		logFile.write("Sending control request, turning: %s, delay min: %d\n\t%s\n" % (isOn, delayMin, binascii.hexlify(request)))

	session, response = sendPacketGetResponse(request, socket, logFile)
	print("Got control response, session: %d" % session)
	if logFile:
		logFile.write("Got control response, turned: %s, delay min: %d" % (isOn, delayMin))

##########################################################################################
# crc
##########################################################################################

def calcCRC(data, key = "00000000000000000000000000000000"): 
	data = binascii.hexlify(data)
	crc = binascii.hexlify(struct.pack('>I', binascii.crc_hqx(binascii.unhexlify(data), 0x1021)))
	data = data + crc[6:8] + crc[4:6]
	crc = crc[6:8] + crc[4:6] + binascii.hexlify(key)
	crc = binascii.hexlify(struct.pack('>I', binascii.crc_hqx(binascii.unhexlify(crc), 0x1021)))
	data = data + crc[6:8] + crc[4:6]
	return bytearray(binascii.unhexlify(data))

def calcCRC2(data, isLogin):
	data = bytearray(binascii.unhexlify("fef052000232a10000000000340001000000000000000000dd879d5a00000000000000000000f0fe1c003b1800003938333200000000000000000000000000000000000000000000000000000000"))
	crc = calcCrc16OnBufferBytes(data, 4129)
	# print("calculated crc16: %d (%s)" % (crc, hex(crc)))

	bufferNew = bytearray(b'\x00') * 34
	bufferNew[0:2] = pack(crc, 2)
	key = "000000000000000000002c0e3d398700"
	bufferNew[2:34] = binascii.hexlify(key)

	legal_byte = calcCrc16OnBufferBytes(bufferNew, 4129)
	print("legal byte: %s" % hex(legal_byte))
	crc32 = bytearray(b'0x0') * 4
	crc32[0:2] = pack(crc, 2)
	crc32[2:4] = pack(legal_byte, 2)

	print ("final: %s" % binascii.hexlify(crc32))

	return data + crc

def calcCrc16OnBufferBytes(bytes, crc):
	crc_tab = [0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935, 4657, 528, 12915, 8786, 21173, 17044, 29431, 25302, 37689, 33560, 45947, 41818, 54205, 50076, 62463, 58334, 9314, 13379, 1056, 5121, 25830, 29895, 17572, 21637, 42346, 46411, 34088, 38153, 58862, 62927, 50604, 54669, 13907, 9842, 5649, 1584, 30423, 26358, 22165, 18100, 46939, 42874, 38681, 34616, 63455, 59390, 55197, 51132, 18628, 22757, 26758, 30887, 2112, 6241, 10242, 14371, 51660, 55789, 59790, 63919, 35144, 39273, 43274, 47403, 23285, 19156, 31415, 27286, 6769, 2640, 14899, 10770, 56317, 52188, 64447, 60318, 39801, 35672, 47931, 43802, 27814, 31879, 19684, 23749, 11298, 15363, 3168, 7233, 60846, 64911, 52716, 56781, 44330, 48395, 36200, 40265, 32407, 28342, 24277, 20212, 15891, 11826, 7761, 3696, 65439, 61374, 57309, 53244, 48923, 44858, 40793, 36728, 37256, 33193, 45514, 41451, 53516, 49453, 61774, 57711, 4224, 161, 12482, 8419, 20484, 16421, 28742, 24679, 33721, 37784, 41979, 46042, 49981, 54044, 58239, 62302, 689, 4752, 8947, 13010, 16949, 21012, 25207, 29270, 46570, 42443, 38312, 34185, 62830, 58703, 54572, 50445, 13538, 9411, 5280, 1153, 29798, 25671, 21540, 17413, 42971, 47098, 34713, 38840, 59231, 63358, 50973, 55100, 9939, 14066, 1681, 5808, 26199, 30326, 17941, 22068, 55628, 51565, 63758, 59695, 39368, 35305, 47498, 43435, 22596, 18533, 30726, 26663, 6336, 2273, 14466, 10403, 52093, 56156, 60223, 64286, 35833, 39896, 43963, 48026, 19061, 23124, 27191, 31254, 2801, 6864, 10931, 14994, 64814, 60687, 56684, 52557, 48554, 44427, 40424, 36297, 31782, 27655, 23652, 19525, 15522, 11395, 7392, 3265, 61215, 65342, 53085, 57212, 44955, 49082, 36825, 40952, 28183, 32310, 20053, 24180, 11923, 16050, 3793, 7920];
	for byte in bytes:
		crc = 0xFFFF & ((crc << 8) ^ crc_tab[((crc >> 8) ^ byte) & 255])

	return crc

##########################################################################################
# socket helpers
##########################################################################################

def getDataFromResponseHeader(header):
	length = unpack(header[2:4])
	session = unpack(header[8:12])
	return session, (length - g_header_size_bytes)

def recvResponse(socket):
	responseHeader = bytearray(socket.recv(g_header_size_bytes))
	assert len(responseHeader) >= g_header_size_bytes, "Respone header can't be smaller than %d bytes, got %d bytes, exiting" % (g_header_size_bytes, len(responseHeader))
	respSession, lengthLeft = getDataFromResponseHeader(responseHeader)
	responseBody = socket.recv(lengthLeft)
	return respSession, bytearray(responseHeader) + bytearray(responseBody)

def sendPacketGetResponse(request, socket, logFile = None):
	socket.send(request)
	session, response = recvResponse(socket)
	assert session != 0, "Got session 0 in response"
	return session, response

def openSocket():
	print ("Openning socket")
	clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientsocket.connect((g_switcher_ip, g_port))
	print("Socket connected to %s:%d" % (g_switcher_ip, g_port))

	return clientsocket

def getState():
	socket = openSocket()
	session = sendLocalSignIn(socket)
	isOn = sendPhoneState(session, socket)
	return 1 if isOn else 0

def control(on, timeMin):
	socket = openSocket()
	session = sendLocalSignIn(socket)
	isOn = sendPhoneState(session, socket)
	onSign = 1 if on else 0
	sendControl(onSign , timeMin, session, socket)

def parseArgs():
	parser = argparse.ArgumentParser(description='Help me')
	modeChoices = ["on", "off", "get_state"]
	parser.add_argument('-m','--mode', dest='mode', choices=modeChoices, required=True)
	parser.add_argument('-t','--time', dest='timeMin', default=0, type=int, required=False)

	return vars(parser.parse_args())

args = parseArgs()
mode = args['mode']
if mode == 'get_state':
	rc = getState()
	sys.exit(rc)
elif mode == 'on' or mode == 'off':
	control(mode == 'on', args['timeMin'])
else:
	assert False, "Unexpected mode"
