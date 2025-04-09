import sys
import time
from utils import bytes_to_hexstr
from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString

# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class PrintObserver(CardObserver):
    def __init__(self, bridge):
        self.bridge = bridge

    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        if addedcards:
            self.bridge._has_card = True
            self.bridge.conn.connect()

        if removedcards:
            self.bridge._has_card = False

class BRIDGE_PYSCARD(object):
    def __init__(self, reader_string, hw_debug):
        self.nfc = None
        self._debug = hw_debug
        self.recv_buff = None
        self._has_card = False

        if not self.connect_reader(reader_string):
            raise ValueError(f"Unable to find {reader_string} reader")

    def connect_reader(self, find_me):
        r = readers()
        for i in range(len(r)):
            if str(r[i]).find(find_me) != -1:
                self.conn = r[i].createConnection()

                try:
                    self.conn.connect()
                    self._has_card = True
                except:
                    pass

                self.cardmonitor = CardMonitor()
                self.cardobserver = PrintObserver(self)
                self.cardmonitor.addObserver(self.cardobserver)

                return True
        return False

    def recv(self):
        if self._debug:
            if self.recv_buff[-2:] == b"\x90\x00":
                print(f"[{color('+', fg='green')}] PYSCARD <= {bytes_to_hexstr(self.recv_buff)}")
            else:
                print(f"[{color('-', fg='red')}] PYSCARD <= {bytes_to_hexstr(self.recv_buff)}")

        return self.recv_buff

    def send(self, data):
        if self._debug:
            print_data = bytes_to_hexstr(bytes(data))
            print(f"[{color('+', fg='green')}] PYSCARD => send = {color(print_data, fg='yellow')}")

        data, sw1, sw2 = self.conn.transmit(data)
        self.recv_buff = bytes(data + [sw1, sw2])

    def sendToNfc(self, data):
        self.send(data)

    def nfcFindCard(self):
        time.sleep(1)
        if self._has_card:
            return True
        return "noCard"

    def nfcGetRecData(self):
        recvdata = self.recv()
        if recvdata == None:
            raise ValueError("Did not recieve any data from PYSCARD")
        return recvdata

    def sendRaw(self, raw_bytes):
        context = []

        if(isinstance(raw_bytes, str)):
            context += list( bytes.fromhex(raw_bytes.replace(" ", "")) )
        elif (isinstance(raw_bytes, bytes)):
            context += list(raw_bytes)
        elif(isinstance(raw_bytes, list)):
            context += raw_bytes
        else:
            raise ValueError("Dont know how to process raw_bytes")

        self.send(context)
        recdata = self.recv()

        return recdata