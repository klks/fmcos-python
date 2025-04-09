import sys
from utils import bytes_to_hexstr

# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class BRIDGE_PM3(object):
    def __init__(self, hw_debug, pm3=None):
        self.nfc = None
        self.self._debug = hw_debug
        if pm3 == None:
            raise ValueError("Need a pm3 instance")
        self.pm3 = pm3
        self.recv_buff = None

    def recv(self):
        ret_buff = bytes.fromhex(self.recv_buff)

        if self.self._debug:
            if ret_buff[-2:] == b"\x90\x00":
                print(f"[{color('+', fg='green')}] PM3 <= {self.recv_buff}")
            else:
                print(f"[{color('-', fg='red')}] PM3 <= {self.recv_buff}")

        #Convert to bytes and return
        return ret_buff

    def send(self, data, select=False):
        exec_cmd =  "hf 14a apdu -k"

        if select:
            exec_cmd += "s" #activate field and select card
        
        exec_cmd += "d " #full APDU package

        #Convert bytearray to string
        exec_cmd += bytearray(data).hex()

        if self.self._debug:
            print(f"[{color('+', fg='green')}] PM3 => exec_cmd = {color(exec_cmd, fg='yellow')}")

        self.pm3.console(exec_cmd)
        self.recv_buff = self.extract_ret(self.pm3.grabbed_output.split('\n'))

    def extract_ret(self, ret):
        for line in ret:
            if line.find("<<< ") != -1:
                ret_data = line.split(" ")[2]
                return ret_data
        return None

    def sendToNfc(self, data):
        enable_select = False
        if len(data) > 5 and data[0]==0x00 and data[1]==0xA4 and (data[2]==0x00 or data[2]==0x04) and data[3]==0x00:
            enable_select = True
        self.send(data, select=enable_select)

    def nfcFindCard(self):
        self.pm3.console("hf 14a info")

        for line in self.pm3.grabbed_output.split("\n"):
            if line.find("UID:") != -1:
                #print(line)
                return line
        return "noCard"

    def nfcGetRecData(self):
        # sleep(0.1)
        recvdata = self.recv()
        if recvdata == None:
            raise ValueError("Did not recieve any data from PM3")
        return recvdata