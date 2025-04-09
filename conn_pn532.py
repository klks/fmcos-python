import sys
import serial
from time import sleep
from utils import bytes_to_hexstr

# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class BRIDGE_PN532(object):
    def __init__(self, com_port, hw_debug):
        self.nfc = None
        self._debug = hw_debug
        self.com_port = com_port
        self.NfcReady()

    def recv(self):
        data = self.nfc.read(100)
        sleep(0.05)
        if self._debug:
            print(f"[{color('+', fg='green')}] PN532 <= {bytes_to_hexstr(data)}")
        return data

    def send(self, data):
        if self._debug:
            print(f"[{color('+', fg='green')}] PN532 => {bytes_to_hexstr(data)}")

        self.nfc.write(data)
        sleep(0.05)

    def NfcReady(self):
        try:
            self.nfc = serial.Serial(self.com_port, 115200, timeout=1)
        except:
            print( f"{color('-', fg='red')} Unable to open COM port" )
            sys.exit(-1)
        self.send(b'\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x03\xFD\xD4\x14\x01\x17\x00')
        self.recv()

    def sendToNfc(self, data, custom_data=False):
        if not custom_data:
            data = [0xD4, 0x40, 0x01] + data
        len = 0
        dsum = 0
        for i in data:
            len = len + 1
            dsum = dsum + i
        lcs = 0xFF - len + 0x01
        dcs = 0xFF - dsum % 0x100 + 0x01
        redata = b'\x00\x00\xff' + bytes([len, lcs]) + bytes(data) + bytes([dcs, 0x00])
        self.send(redata)
        return redata

    def nfcFindCard(self):
        # sleep(0.1)
        self.sendToNfc([0xD4, 0x4A, 0x01, 0x00], custom_data=True)
        recdata = self.recv()
        if recdata[11:13] == b'\xd5\x4b':
            uid = recdata[19:23]
            return uid
        else:
            return 'noCard'

    def nfcGetRawRecData(self):
        recvdata = self.recv()
        try:
            data_len = recvdata[9]
            recvdata = recvdata[11:11 + data_len]
            if recvdata == 'error':
                raise ValueError("nfcGetRawRecData returned error [1]")
            return recvdata[3:]
        except:
            raise ValueError("nfcGetRawRecData returned error [2]")

    def nfcGetRecData(self):
        # sleep(0.1)
        recvdata = self.recv()
        try:
            data_len = recvdata[9]
            recvdata = recvdata[11:11 + data_len]
            if recvdata == 'error' or recvdata[0:3] != b'\xd5\x41\x00':
                raise ValueError("nfcGetRecData returned error [1]")

            return recvdata[3:]
        except:
            raise ValueError("nfcGetRecData returned error [2]")

    def sendRaw(self, raw_bytes):   #This is used for PN532
        context = []

        if(isinstance(raw_bytes, str)):
            context += list( bytes.fromhex(raw_bytes.replace(" ", "")) )
        elif (isinstance(raw_bytes, bytes)):
            context += list(raw_bytes)
        elif(isinstance(raw_bytes, list)):
            context += raw_bytes
        else:
            raise ValueError("Dont know how to process raw_bytes")

        if self._debug:
            print(f"[{color('=', fg='yellow')}] PN532_FMCOS => " + bytes_to_hexstr(bytes(context)) )

        self.sendToNfc(context)
        recdata = self.nfcGetRecData()

        if self._debug:
            print(f"[{color('=', fg='yellow')}] PN532_RAW => " + bytes_to_hexstr(recdata))
        return recdata