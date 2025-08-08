import sys

# Optional color support for prettier console logs. Install with: `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class BRIDGE_PM3(object):
    """Thin wrapper around a Proxmark3 console to send/receive ISO14443-4 APDUs.

    This class builds Proxmark3 commands (e.g., `hf 14a apdu`) and parses the console output.

    Attributes:
        pm3: A Proxmark3 Python binding/console instance with `.console(cmd)` and `.grabbed_output`.
        _debug: When True, prints colored TX/RX traces and status words.
        recv_buff: Last raw hex string received from PM3 (e.g., "9000" or response data + SW).
    """
    def __init__(self, hw_debug, pm3=None):
        # Placeholder for possible future NFC state. Not used directly in this bridge.
        self.nfc = None

        # Enable/disable verbose logging.
        self._debug = hw_debug  # fixed typo: self.self._debug -> self._debug

        # The Proxmark3 interface/console object is required.
        if pm3 is None:
            raise ValueError("Need a pm3 instance")
        self.pm3 = pm3
        self.recv_buff = None

    def recv(self):
        """Return last captured response from PM3 as bytes.

        Expects `self.recv_buff` to be a hex string as produced by `extract_ret`.
        """
        ret_buff = bytes.fromhex(self.recv_buff)

        if self._debug:
            if ret_buff[-2:] == b"\x90\x00":
                print(f"[{color('+', fg='green')}] PM3 <= {self.recv_buff}")
            else:
                print(f"[{color('-', fg='red')}] PM3 <= {self.recv_buff}")

        #Convert to bytes and return
        return ret_buff

    def send(self, data, select=False):
        """Send an APDU via Proxmark3 `hf 14a apdu` and capture the response.

        Args:
            data (bytes|bytearray|list[int]): APDU to send.
            select (bool): If True, add the `-s` flag to activate field and select card.

        Note:
            - `-k` keeps the field active (don't power down).
            - `-s` selects the card (useful before a SELECT APDU).
            - `-d` expects a full APDU (CLA INS P1 P2 [Lc Data] [Le]).
        """
        exec_cmd =  "hf 14a apdu -k"  # keep field active

        if select:
            exec_cmd += "s"  # activate field and select card
        
        exec_cmd += "d "  # full APDU package (data follows)

        # Convert APDU to hex string (no spaces)
        exec_cmd += bytearray(data).hex()

        if self._debug:
            print(f"[{color('+', fg='green')}] PM3 => exec_cmd = {color(exec_cmd, fg='yellow')}")

        # Execute the command; the PM3 binding is expected to populate `.grabbed_output`.
        self.pm3.console(exec_cmd)
        self.recv_buff = self.extract_ret(self.pm3.grabbed_output.split('\n'))

    def extract_ret(self, ret):
        """Extract the last APDU response hex string from PM3 console output lines.

        PM3 typically logs APDU RX lines prefixed with "<<< ". We pick the data field.

        Args:
            ret (Iterable[str]): Lines of console output.

        Returns:
            str | None: Hex string of APDU response (data + SW), or None if not found.
        """
        for line in ret:
            if line.find("<<< ") != -1:
                ret_data = line.split(" ")[2]
                return ret_data
        return None

    def sendToNfc(self, data):
        """Convenience wrapper: auto-enable select for ISO SELECT APDUs.

        Detects SELECT by checking header: 00 A4 00/04 00, then calls `send(select=True)`.
        """
        enable_select = False
        if len(data) > 5 and data[0]==0x00 and data[1]==0xA4 and (data[2]==0x00 or data[2]==0x04) and data[3]==0x00:
            enable_select = True
        self.send(data, select=enable_select)

    def nfcFindCard(self):
        """Trigger a 14a inventory and return the UID line or 'noCard'."""
        self.pm3.console("hf 14a info")

        for line in self.pm3.grabbed_output.split("\n"):
            if line.find("UID:") != -1:
                #print(line)
                return line
        return "noCard"

    def nfcGetRecData(self):
        """Get last received data as bytes; raise if nothing is available."""
        # sleep(0.1)
        recvdata = self.recv()
        if recvdata == None:
            raise ValueError("Did not recieve any data from PM3")
        return recvdata