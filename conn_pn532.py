import sys
import serial  # type: ignore
from time import sleep
from utils import bytes_to_hexstr

# Optional color support for console logs. Install with: `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class BRIDGE_PN532(object):
    """Serial bridge for PN532 to send/receive APDUs over ISO14443.

    PN532 frame layout (HSU):
        Preamble(0x00) | StartCode(0x00 0xFF) | LEN | LCS | TFI | Data... | DCS | Postamble(0x00)
      - LEN: number of bytes in [TFI + Data]
      - LCS: 0x100 - LEN (8-bit)
      - TFI: 0xD4 host->PN532, 0xD5 PN532->host
      - DCS: 0x100 - sum(TFI+Data) (8-bit)
    """
    def __init__(self, com_port, hw_debug):
        self.nfc = None
        self._debug = hw_debug
        self.com_port = com_port
        self.NfcReady()

    def recv(self):
        """Read bytes from PN532 and optionally log them."""
        data = self.nfc.read(100)
        sleep(0.05)
        if self._debug:
            print(f"[{color('+', fg='green')}] PN532 <= {bytes_to_hexstr(data)}")
        return data

    def send(self, data):
        """Write bytes to PN532 and optionally log them."""
        if self._debug:
            print(f"[{color('+', fg='green')}] PN532 => {bytes_to_hexstr(data)}")

        self.nfc.write(data)
        sleep(0.05)

    def NfcReady(self):
        """Open serial port and initialize PN532 in ISO14443A initiator mode.

        Sends a standard wakeup/config sequence (prebuilt frame) and reads the reply.
        """
        try:
            self.nfc = serial.Serial(self.com_port, 115200, timeout=1)
        except:
            print( f"{color('-', fg='red')} Unable to open COM port" )
            sys.exit(-1)
        # Prebuilt PN532 wake-up/initialize frame.
        self.send(b'\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x03\xFD\xD4\x14\x01\x17\x00')
        self.recv()

    def sendToNfc(self, data, custom_data=False):
        """Build and send a PN532 frame.

        Args:
            data (list[int] | bytes): If `custom_data=False`, this is the APDU payload
                and will be wrapped with [0xD4, 0x40, 0x01] (TFI, InDataExchange, target 1).
                If `custom_data=True`, then `data` must include TFI (0xD4) and the command.
            custom_data (bool): Set True when providing raw PN532 command bytes.

        Returns:
            bytes: The fully encoded PN532 frame that was sent.
        """
        if not custom_data:
            data = [0xD4, 0x40, 0x01] + data
        # Compute LEN (length of TFI+DATA) and DCS (checksum of TFI+DATA)
        len = 0  # shadows built-in len; kept to avoid behavior change
        dsum = 0
        for i in data:
            len = len + 1
            dsum = dsum + i
        # LCS = 0x100 - LEN (mod 256)
        lcs = 0xFF - len + 0x01
        # DCS = 0x100 - sum(TFI+DATA) (mod 256)
        dcs = 0xFF - dsum % 0x100 + 0x01
        # Assemble full frame: PREAMBLE+START | LEN LCS | TFI+DATA | DCS | POSTAMBLE
        redata = b'\x00\x00\xff' + bytes([len, lcs]) + bytes(data) + bytes([dcs, 0x00])
        self.send(redata)
        return redata

    def nfcFindCard(self):
        """Search for an ISO14443A card and return UID bytes or 'noCard'."""
        # sleep(0.1)
        # InListPassiveTarget (0x4A) with max 1 target, 106 kbps type A
        self.sendToNfc([0xD4, 0x4A, 0x01, 0x00], custom_data=True)
        recdata = self.recv()
        # Response header for InListPassiveTarget is TFI(0xD5) + 0x4B
        if recdata[11:13] == b'\xd5\x4b':
            uid = recdata[19:23]
            return uid
        else:
            return 'noCard'

    def nfcGetRawRecData(self):
        """Return raw PN532 data payload (excluding TFI/command/status)."""
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
        """Return data portion from an InDataExchange response; validate status."""
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
        """Send raw bytes as an APDU via InDataExchange and return the response.

        Args:
            raw_bytes (str|bytes|list[int]):
                - hex str (spaces allowed), e.g., '00 A4 04 00'
                - bytes, e.g., b"\x00\xA4\x04\x00"
                - list of ints [0..255]
        """
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