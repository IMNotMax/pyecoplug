import socket
from datetime import datetime
import struct, time
from threading import Thread
#from .plug import EcoPlug

#-----------------------------
#Copy/pasted everythin from plug.py since the from .plug import Ecoplug wasn't finding the relative directory.

import pprint
from threading import Event
import random

class EcoPlug(object):
    CONNECTION_TIMEOUT = 60

    def __init__(self, data):
        self.plug_data = data
        # Name set for outlet in phone app
        self.name = data[3].decode('utf-8')
        # 'Manufacturer-partial MAC' as unique ID (e.g. 'ECO-123456')
        self.ident = data[2].decode('utf-8')

        self._pending = {}

        self._connected = False
        self._connected_timeout = 0


    def __repr__(self):
        def class_decor(s):
            return '## %s ##' %s
        return pprint.pformat(
                (class_decor(self.__class__.__name__), self.plug_data[3])
                )

    def _connect(self):
        if self._connected:
            self._connected_timeout = time.time() + self.CONNECTION_TIMEOUT
            return

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.connect((self.plug_data[-2], self.plug_data[-1]))

        self._connected = True
        self._connected_timeout = time.time() + self.CONNECTION_TIMEOUT

        self._start()

    def _timeout_connection(self, from_recv_thread=False):
        if not self._connected or time.time() < self._connected_timeout:
            return False

        # The timeout has occurred
        # stop the thread
        if not from_recv_thread:
            self._stop()
        else:
            self._running = False

        # close the connection
        self._socket.close()
        self._connected = False

        return True

    def _start(self):
        self._pending = {}
        self._running = True
        self._thread = Thread(target=self._recv_thread)
        self._thread.start()

    def _stop(self):
        self._running = False
        self._thread.join()

    def stop(self):
        if self._connected:
           self._connected = False
           self._stop()
           self._socket.close()

    def _recv_thread(self):
        while self._running:
            if self._timeout_connection(True):
                break

            try:
                self._socket.settimeout(0.1)
                data = self._socket.recv(1000)
                self._socket.settimeout(None)
                
                xid, payload_length = struct.unpack_from('<HH', data, 6)
                payload = bytearray(data[128: 128 + payload_length])
                data = bytearray(data[:128])

                if xid in self._pending:
                    _, _, cb = self._pending[xid]
                    del(self._pending[xid])
                    if cb: cb(data, payload)

            except socket.timeout:
                continue

    def xmit(self, data):
        self._socket.send(data)

    def send_payload(self, flags, command, data, cb = None):
        xid = random.randint(0, 65535)
        main_body = struct.pack('<HLHH6s32s32s32sLLLL',
                flags,
                command,
                xid,
                len(data),
                self.plug_data[1],
                self.plug_data[2],
                self.plug_data[3],
                self.plug_data[4],
                0,      # The plug returns data in this field
                int(time.time() * 1000) & 0xffffffff,
                0,
                0x0d5249ae)

        self._pending[xid] = (main_body, data, cb)
        self.xmit(main_body + data)
        self.xmit(main_body + data)
        self.xmit(main_body + data)

    def turn_on(self):
        self._connect()
        self.send_payload(0x16, 0x05, b'\x01\x01')

    def turn_off(self):
        self._connect()
        self.send_payload(0x16, 0x05, b'\x01\x00')

    def is_on(self):
        self._connect()

        # create an event which we can wait upon
        e = Event()
        state = [ False ]
        def cb(packet, payload):
            state[0] = payload[1] == 1
            e.set()
        for i in range(10):
            self.send_payload(0x17, 0x05, b'', cb)
            if e.wait(1):
                break
            self.stop()
            self._connect()
        return state[0]

#This is the end of the copy/paste from plug.py. Above this line.
#-----------------------------


def normalize_string(x):
    if type(x) == bytes:
        return x.rstrip(b' \t\r\n\0')
    return x

class EcoDiscovery(object):
    UDP_PORT = 8900

    def __init__(self, on_add, on_remove):
        self.on_add = on_add
        self.on_remove = on_remove
        self.discovered = {}
        print("Printing self.discovered in def __init__:",self.discovered)

        self.running = False

    def iterate(self):
        for m, p in self.discovered.items():
            yield p[1]

    def start(self):
        self.running = True
        self.thread = Thread(target=self.poll_discovery)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', self.UDP_PORT))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.settimeout(0.5)

        self.thread.start()

    def stop(self):
        self.running = False
        self.thread.join()
        for m, p in self.discovered.items():
            self.on_remove(p[1])
            p[1].stop()
        self.discovered.clear()
        self.socket.close()

    def process_packet(self, pkt):
        now = time.time()
        mac_addr = pkt[-3]
        print("Printing self.discovered in process_packet:",self.discovered)
        if not mac_addr in self.discovered:
            plug = EcoPlug(pkt)
            print("Printing plug in process_packet:",plug)
            self.on_add(plug)
            self.discovered[mac_addr] = (now, plug)
        else:
            plug = self.discovered[mac_addr][1]
            plug.plug_data = pkt
            self.discovered[mac_addr] = (now, plug)

    def prune_stale(self):
        now = time.time()
        to_remove = []
        for mac, p in self.discovered.items():
            if now - p[0] >= 30:
                to_remove.append(mac)
        for mac in to_remove:
            plug = self.discovered[mac][1]
            self.on_remove(plug)
            plug.stop()
            del(self.discovered[mac])

    def poll_discovery(self):
        broadcast = True
        while self.running:
            if broadcast:
                last_broadcast = time.time()

                now = datetime.now()
                packet = bytearray(b'\x00' * 128)
                struct.pack_into('<HBBL', packet, 24, now.year, now.month, now.day, now.hour * 3600 + now.minute * 60 + now.second)
                self.socket.sendto(packet, ('255.255.255.255', 5888))
                self.socket.sendto(packet, ('255.255.255.255', 5888))
                self.socket.sendto(packet, ('255.255.255.255', 5888))
                self.socket.sendto(packet, ('255.255.255.255', 25))
                self.socket.sendto(packet, ('255.255.255.255', 25))
                self.socket.sendto(packet, ('255.255.255.255', 25))

                broadcast = False

            elif time.time() - last_broadcast >= 10:
                broadcast = True

            else:
                try:
                    data, _ = self.socket.recvfrom(408)
                    pkt = list(struct.unpack('<L6s32s32s32sHHBBLl64s64sH10s12s16s16s16sLLLLH30s18s18sL', data))
                    pkt = tuple([normalize_string(x) for x in pkt])
                    self.process_packet(pkt)

                except socket.timeout:
                    continue
                finally:
                    self.prune_stale()


if __name__ == '__main__':
    def on_add(pkt):
        print('Add:', repr(pkt))
        pkt.turn_on()
        print(pkt.is_on())
    def on_remove(pkt):
        print('Remove:', repr(pkt))

    try:
        e = EcoDiscovery(on_add, on_remove)
        e.start()
        time.sleep(180)
    finally:
        for plug in e.iterate():
            plug.turn_off()
        e.stop()


