#!/usr/bin/env python3

"""
from a ubuntu env:
docker run --rm -it --network host ubuntu
apt update ; apt install -y python3 python3-pip
pip3 install pycryptodome
chmod +x tapofakelan.py
python3 tapofakelan.py
"""

import struct
import sys
import zlib
import json
import base64
import socket
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64
import http.server, ssl
import threading

PKT_ONBOARD_REQUEST  = b'\x11\x00' # \x02\x0D\x87\x23'
PKT_ONBOARD_RESPONSE = b'"\x01'    # \x02\r\x87#'

def eprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)

# note: pkcs7.PKCS7Encoder().encode is broken
# https://stackoverflow.com/questions/43199123/encrypting-with-aes-256-and-pkcs7-padding
def pkcs7_pad(input_str, block_len=16):
    return input_str + chr(block_len-len(input_str)%block_len)*(block_len-len(input_str)%16)

def pkcs7_unpad(ct):
    return ct[:-ord(ct[-1])]

class TpLinkCipher:
    def __init__(self, b_arr: bytearray, b_arr2: bytearray):
        self.iv = b_arr2
        self.key = b_arr

    def encrypt(self, data):
        data = pkcs7_pad(data)
        cipher = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        encrypted = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted).decode().replace("\r\n","")

    def decrypt(self, data: str):
        aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        pad_text = aes.decrypt(base64.b64decode(data.encode())).decode()
        return pkcs7_unpad(pad_text)

def extract_pkt_id(packet):
    return packet[8:12]

def extract_payload_from_package(packet):
    return packet[16:]

def extract_payload_from_package_json(packet):
    return json.loads(packet[16:])

def build_packet_for_payload(payload, pkt_type, pkt_id=b"\x01\x02\x03\x04"):

    len_bytes = struct.pack(">h", len(payload))
    skeleton = b'\x02\x00\x00\x01'+len_bytes+pkt_type+pkt_id+b'\x5A\x6B\x7C\x8D'+payload
    calculated_crc32 = zlib.crc32(skeleton) & 0xffffffff
    calculated_crc32_bytes = struct.pack(">I", calculated_crc32)
    re = skeleton[0:12] + calculated_crc32_bytes + skeleton[16:]
    return re

def build_packet_for_payload_json(payload, pkt_type, pkt_id=b"\x01\x02\x03\x04"):
    return build_packet_for_payload(json.dumps(payload).encode(), pkt_type, pkt_id)

def process_encrypted_handshake(response):
    encryptedSessionKey = response["result"]["encrypt_info"]["key"]
    encryptedSessionKeyBytes  = base64.b64decode(encryptedSessionKey.encode())
    ourPrivKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA2GS/uDBXVOJmPYSxCH1nvC5Pe2+Onky+BMQX4eUjgIV+aC/i
15TZLDF9HYRRFpau0bE7C5LYDoS/d+QOelj5dcJWbf8+/0q4GIgvpj4IOzo0ml/+
kISjN1yPJ6i1SACC2AwDk1w0f1mQbV0TZnVQiRYRUCkui3Ww6RFGO/plssdcMVQI
5i7oWCA8tSHuGBIhjaSb8t86DtY6WEkyrAu56Pi7Z21hw8kYEYKK0VCD2vvsHcek
yQYLRkHmOw4WUrKx1897uiL+6Lq4M1Q/aSR+fvGofCF6QLrtzmKpMpzJH5CHycNA
pjGsNcQUxwV8fKtV+/ZkmYHfiB46+0CZWlw1LwIDAQABAoIBAQCY6lkw57hPG830
GxifTz9HE9LG/4ZhBwoghBH8Z9g2sh8psO00OtNdD3vCqAZFWCYhuIRpIVPcrqI/
LsGsY8OlG7fH81+pODvv2g0SBTP75p3VmZBiv9g2/wmKlQXF49aSparBL59Jfxk4
r1VOSginVxjU9MUXeAuUJ8jiCYhkVH+hg+jYaQU8Vl0FvPQWM2cerxCoJmeCOnm0
+BLuHpPBKOmPHKtY9Vwm1AJ1xKshRlpcpUp+6XaftROpAYTkd2IM6ugrxSEgJpU7
C/FFk1ZEhHxWPfCRs4GlDmAXHR2X0dhh1xCEdbO45v3/64lDFr3nuH53hlFrQ7Zu
qpdait4BAoGBAP0nzlvljZX4Cy3KrhUiGbZkyaJ4WWNgqEFPBS2mRVRbCK9Ois90
S0Cj6AzYxEuRkVGOeoqaIgGaJ6vrbs05FNR8bs0atbaYdKn/1pVFRnbEO3pkRaia
MQL0oEHPwZ5mDN4CSF3jHdXbRGg/1As23BOtuNqlBrndrQPeLixD9izPAoGBANrT
Mr8yrc4qr8hnUu+3tXtJ/M7PFIAAjceZaz6yoTIgPeglDksVEhbGWxIl9+Ud8C1+
AysNez7oqnXuv3JIHUagEikJOGkNgBbFapTFyDUlXAHP5a/d+Gi/OegsheGZR5vf
iixqgtVBdEVSB7DIZYTpgxDJg+XYUOyK3nn4zUmhAoGBAPXa1cdbrWCLD1g+cUgm
4O/I/CWkWbNwqJcchfvqcYRWEJ4oWhjVaUvyoqbvUdvOGGIrTAkVXZdOvd5x/B6k
o/0kh3r7yKP3db2vsBcxuxgWxWi8vwXaEWU8a/LeMLyDgVWOw/ciXdRWaR4Rdv4Z
HiyiV1dIU7rodWG/QfpNWmPzAoGBAIt7P8eb2CmoD/Af3D+sy+NQX/K7EIge0kC+
TBvk5Nb8sjk9FYVKYwNdYEOLLB5BHQ0CW6afq0WILM+LZUDFMtQHyEub8vcTgegB
4lP+VgV6UNFe4Ttes66g5ZpWdug8OebjcEGrisXAOQrOpNRMiFlWNxMGQCrL3ZlJ
U1JQAxrBAoGBANWj/e5ArpWCXwbkOh6zomr9MVwE1H7j3NXhJ34/IOfgDaSbtB0q
biAOEzSw7UncklnvR/g2bu+kajGkv5Az8pqljpIju11veLdcO2iPWoJl7a55bdMc
VooUEgqUXNHpSJ5HamXOL+5ZSWzYY7j23ogzZLu0UHBs0t0LsxgmR5vv
-----END RSA PRIVATE KEY-----"""

    ourPrivCipher = PKCS1_OAEP.new(RSA.importKey(ourPrivKey))
    clearSessionKeyBytes = ourPrivCipher.decrypt(encryptedSessionKeyBytes)
    if not clearSessionKeyBytes:
        raise ValueError("Decryption failed!")

    b_arr = bytearray()
    b_arr2 = bytearray()

    for i in range(0, 16):
        b_arr.insert(i, clearSessionKeyBytes[i])
    for i in range(0, 16):
        b_arr2.insert(i, clearSessionKeyBytes[i + 16])

    cipher = TpLinkCipher(b_arr, b_arr2)
    cleartextDataBytes = cipher.decrypt(response["result"]["encrypt_info"]["data"])
    eprint("handshake payload decrypted as", cleartextDataBytes)
    return json.loads(cleartextDataBytes)

def send_broadcast(packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 5);
    #  sock.settimeout(2)
    sock.sendto(packet, ("255.255.255.255", 20002))
    eprint("packet sent", packet)
    while True:
        data, addr = sock.recvfrom(2048)
        eprint("received", addr, data)
        return data

def handle_incoming_handshake_request(payload, our_ip, owner):
    iv = b"1234567890123456"
    key = b"1234567890123456"
    clearSessionKeyBytes = iv + key

    cipher = TpLinkCipher(iv, key)
    data = { "device_id": "11111111111111111111CE6645443EAE20758575", "http_port": 50443, "connect_type": "wireless", "connect_ssid": "", "owner": owner, "sd_status": "offline" }
    encryptedDataB64 = cipher.encrypt(json.dumps(data))

    rsaPublicKeyOfTheAndroidApp = payload["params"]["rsa_key"].replace("\\n", "\n")
    eprint("public key to be imported", rsaPublicKeyOfTheAndroidApp)
    pubCipher = PKCS1_OAEP.new(RSA.importKey(rsaPublicKeyOfTheAndroidApp))
    encryptedSessionKeyBytes = pubCipher.encrypt(clearSessionKeyBytes)
    encryptedSessionKeyBytesB64 = base64.b64encode(encryptedSessionKeyBytes).decode()


    response_json = {
       "error_code": 0,
       "result": {
            "device_id": "11111111111111111118A86DF4865F41",
            "device_name": "Tapo_Camera",
            "device_type": "SMART.IPCAMERA",
            "device_model": "C110",
            "ip": our_ip,
            "mac": "B8-27-EB-11-11-11",
            "hardware_version": "1.0",
            "firmware_version": "1.1.22 Build 220726 Rel.10212n(4555)",
            "factory_default": True,
            "mgt_encrypt_schm": { "is_support_https": True },
            "encrypt_info": {
                "sym_schm": "AES",
                "key": encryptedSessionKeyBytesB64,
                "data": encryptedDataB64
            }
        }
    }
    return response_json

#credit: https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
def find_our_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    our_ip = s.getsockname()[0]
    s.close()
    return our_ip

def handshake_server(owner):
    our_ip=find_our_ip()
    print("we advertise this IP address to the management app:", our_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", 20002))
    print("listening, waiting for broadcasts")
    while True:
       packet, addr = sock.recvfrom(2048) # buffer size is 1024 bytes
       eprint("received message", addr, packet)
       try:
           request = extract_payload_from_package_json(packet)
       except:
           continue
       response = handle_incoming_handshake_request(request, our_ip, owner)
       pkt_id = extract_pkt_id(packet)
       responsePacket = build_packet_for_payload_json(response, PKT_ONBOARD_RESPONSE, pkt_id)
       eprint("sending response", responsePacket)
       sock.sendto(responsePacket, addr)
    sock.close()

# note: the Tapo plugs advertise the owner hash without any fancy encryption
def find_owner():
    while True:
        handshake_packet = send_broadcast(build_packet_for_payload_json({"params":{"rsa_key":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2GS/uDBXVOJmPYSxCH1n\nvC5Pe2+Onky+BMQX4eUjgIV+aC/i15TZLDF9HYRRFpau0bE7C5LYDoS/d+QOelj5\ndcJWbf8+/0q4GIgvpj4IOzo0ml/+kISjN1yPJ6i1SACC2AwDk1w0f1mQbV0TZnVQ\niRYRUCkui3Ww6RFGO/plssdcMVQI5i7oWCA8tSHuGBIhjaSb8t86DtY6WEkyrAu5\n6Pi7Z21hw8kYEYKK0VCD2vvsHcekyQYLRkHmOw4WUrKx1897uiL+6Lq4M1Q/aSR+\nfvGofCF6QLrtzmKpMpzJH5CHycNApjGsNcQUxwV8fKtV+/ZkmYHfiB46+0CZWlw1\nLwIDAQAB\n-----END PUBLIC KEY-----\n"}}, PKT_ONBOARD_REQUEST))
        try:
            handshake_json = extract_payload_from_package_json(handshake_packet)
            owner = (handshake_json.get("result") or {}).get("owner")
            if not owner:
                clear = process_encrypted_handshake(handshake_json)
                owner = clear.get("owner")
            if owner:
                print("Found owner", owner)
                return owner
        except:
            pass

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def _respond(self, r):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(r).encode())

    def _post_logic(self, post_data):
        return {"error_code": 124}

    def do_GET(self):
        eprint("GET request,\nPath: %s\nHeaders:\n%s\n\n" %( str(self.path), str(self.headers)))
        return  self._respond({"error_code": 123})

    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        print("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n\n" % (
                str(self.path), str(self.headers), post_data.decode('utf-8')))
        response = self._post_logic(post_data)
        eprint("responding", response)
        return self._respond(response)

def start_http_server():
    server_address = ('0.0.0.0', 50443)
    httpd = http.server.HTTPServer(server_address, MyHttpRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   server_side=True,
                                   certfile='domain.pem',
                                   ssl_version=ssl.PROTOCOL_TLS)
    print("http server listening")
    httpd.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=start_http_server, args=()).start()
    owner = find_owner()
    handshake_server(owner)
