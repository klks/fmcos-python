import sys
import time
from utils import bytes_to_hexstr
# Optional pyscard imports; annotate types to avoid unresolved warnings if not installed
from smartcard.System import readers  # type: ignore
from smartcard.CardMonitoring import CardMonitor, CardObserver  # type: ignore
from smartcard.util import toHexString  # type: ignore

# Optional color support .. `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class PrintObserver(CardObserver):
    """Card presence observer that tracks insertion/removal and opens a connection."""
    def __init__(self, bridge):
        self.bridge = bridge

    def update(self, observable, actions):
        """pyscard callback when cards are added/removed."""
        (addedcards, removedcards) = actions
        if addedcards:
            self.bridge._has_card = True
            self.bridge.conn.connect()

        if removedcards:
            self.bridge._has_card = False

class BRIDGE_PYSCARD(object):
    """Bridge using pyscard to send APDUs to a smartcard reader.

    Attributes:
        _debug: Enable TX/RX logging when True.
        conn: pyscard connection object created from a selected reader.
        _has_card: Tracks if a card is currently present (from CardMonitor).
    """
    def __init__(self, reader_string, hw_debug):
        self.nfc = None
        self._debug = hw_debug
        self.recv_buff = None
        self._has_card = False

        if not self.connect_reader(reader_string):
            raise ValueError(f"Unable to find {reader_string} reader")

    def connect_reader(self, find_me):
        """Find a reader whose name contains `find_me` and start monitoring."""
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
        """Return the last APDU response (bytes) and optionally log SW1SW2."""
        if self._debug:
            if self.recv_buff[-2:] == b"\x90\x00":
                print(f"[{color('+', fg='green')}] PYSCARD <= {bytes_to_hexstr(self.recv_buff)}")
            else:
                print(f"[{color('-', fg='red')}] PYSCARD <= {bytes_to_hexstr(self.recv_buff)}")

        return self.recv_buff

    def send(self, data):
        """Transmit APDU bytes and store response+status in `recv_buff`."""
        if self._debug:
            print_data = bytes_to_hexstr(bytes(data))
            print(f"[{color('+', fg='green')}] PYSCARD => send = {color(print_data, fg='yellow')}")

        data, sw1, sw2 = self.conn.transmit(data)
        self.recv_buff = bytes(data + [sw1, sw2])

    def sendToNfc(self, data):
        """Compatibility shim to match other bridges' interface."""
        self.send(data)

    def nfcFindCard(self):
        """Return True if a card is present, otherwise 'noCard'."""
        time.sleep(1)
        if self._has_card:
            return True
        return "noCard"

    def nfcGetRecData(self):
        """Return last received bytes, raising if none."""
        recvdata = self.recv()
        if recvdata == None:
            raise ValueError("Did not recieve any data from PYSCARD")
        return recvdata

    def sendRaw(self, raw_bytes):
        """Send raw APDU in multiple input forms (hex str/bytes/list[int])."""
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