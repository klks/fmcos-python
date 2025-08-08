import sys
import os
import struct
import datetime
from enum import IntEnum
from utils import strToint16, bytes_to_hexstr
from Crypto.Cipher import DES, DES3  # type: ignore
from Crypto.Util.Padding import pad, unpad  # type: ignore

# Optional color support .. `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

class ApplicationBlock(IntEnum):
    Temporary = 0x00,
    Permenant = 0x01

class Protection(IntEnum):
    LineProtect = 0x80,
    LineProtectEncrypt = 0xC0

class BalanceType(IntEnum):
    Passbook = 0x01,
    Wallet = 0x02

class TransactionProofType(IntEnum):
    Passbook = 0x01,
    Wallet = 0x02,
    Debit = 0x03,
    Withdrawals = 0x04,
    PassbookPurchase = 0x05,
    WalletPurchase = 0x06,
    Overdraft = 0x07,
    Compound = 0x09

class CPUFileType(IntEnum):
    MFDF = 0x38,    #Catalog file MF or DF
    BinFile = 0x28,
    FixLength = 0x2A,
    VariableLength = 0x2C,
    LoopFile = 0x2E,
    Wallet = 0x2F,
    Keyfile = 0x3f,

class KeyType(IntEnum):
    DESEncrypt = 0x30,
    DESDecrypt = 0x31,
    DESMAC = 0x32,
    InternalKey = 0x34,
    FileLineProtectionKey = 0x36,
    UnlockPinKey = 0x37,                    #Also called Unlock Password Key
    ChangePinKey = 0x38,                    #Also called Reload/Reinstall Password Key
    ExternalAuthenticationKey = 0x39,
    PinKey = 0x3a,                          #Also called Password Key
    OverdrawLimitKey = 0x3c,                #Also called Modify Overdraft Limit Key
    DebitKey = 0x3d,                        #Also called Circle/Withdrawal Key
    PurchaseKey = 0x3e,                     #Also called Consumption Key
    CreditKey = 0x3f                        #Also called Captive/Trap/Stored/Recharge Key

def parse_return_code(ret_code, console_print=True):
    """Decode SW1/SW2 or extended status words into a readable message.

    Args:
        ret_code (bytes): Buffer ending in SW1 SW2.
        console_print (bool): If True, print a human-readable summary.
    """
    if ret_code == None:
        if console_print:
            print("Return code empty")
        return

    if len(ret_code) < 2:
        if console_print:
            print(f"Insufficient length of ret_code : {len(ret_code)}")

    ret_string = "Unknown return code"

    match ret_code[0]:
        case 0x62:
            if ret_code[1] >= 2 and ret_code[1] <= 0x80:
                ret_string = "Triggering by the card"
            match ret_code[1]:
                case 0x81:
                    ret_string = "Part of returned data may be corrupted"
                case 0x82:
                    ret_string = "End of file or record reached before reading Ne bytes"
                case 0x83:
                    ret_string = "Selected file deactivated"
                case 0x84:
                    ret_string = "File control information not formatted"
                case 0x85:
                    ret_string = "Selected file in termination state"
                case 0x86:
                    ret_string = "No input data available from a sensor on the card"

        case 0x63:
            if ret_code[1] == 0x81:
                ret_string = "File filled up by the last write"
            elif (ret_code[1] & 0xF0) == 0xC0:
                ret_string = "Counter from 0 to 15 encoded by 'X'(SW2&0xF)"

        case 0x64:
            if ret_code[1] >= 2 and ret_code[1] <= 0x80:
                ret_string = "Triggering by the card"
            elif ret_code[1] == 1:
                ret_string = "Immediate response required by the card"

        case 0x65:
            if ret_code[1] == 0x81:
                ret_string = "Memory failure"

        case 0x67:
            if ret_code[1] == 0x00:
                ret_string = "Invalid length"

        case 0x68:
            match ret_code[1]:
                case 0x81:
                    ret_string = "Logical channel not supported"
                case 0x82:
                    ret_string = "Secure messaging not supported"
                case 0x83:
                    ret_string = "Last command of the chain expected"
                case 0x84:
                    ret_string = "Command chaining not supported"

        case 0x69:
            match ret_code[1]:
                case 0x81:
                    ret_string = "Command incompatible with file structure"
                case 0x82:
                    ret_string = "Security status not satisfied"
                case 0x83:
                    ret_string = "Authentication method blocked"
                case 0x84:
                    ret_string = "Reference data not usable"
                case 0x85:
                    ret_string = "Conditions of use not satisfied"
                case 0x86:
                    ret_string = "Command not allowed (no current EF)"
                case 0x87:
                    ret_string = "Expected secure messaging data objects missing"
                case 0x88:
                    ret_string = "Incorrect secure messaging data objects"

        case 0x6A:
            match ret_code[1]:
                case 0x80:
                    ret_string = "Incorrect parameters in the command data field"
                case 0x81:
                    ret_string = "Function not supported"
                case 0x82:
                    ret_string = "File or application not found"
                case 0x83:
                    ret_string = "Record not found"
                case 0x84:
                    ret_string = "Not enough memory space in the file"
                case 0x85:
                    ret_string = "Nc inconsistent with TLV structure"
                case 0x86:
                    ret_string = "Incorrect parameters P1-P2"
                case 0x87:
                    ret_string = "Nc inconsistent with parameters P1-P2"
                case 0x88:
                    ret_string = "Referenced data or reference data not found"
                case 0x89:
                    ret_string = "File already exists"
                case 0x8A:
                    ret_string = "DF name already exists"

        case 0x6D:
            match ret_code[1]:
                case 0x00:
                    ret_string = "Invalid INS parameter"

        case 0x6E:
            match ret_code[1]:
                case 0x00:
                    ret_string = "Invalid CLA parameter"

        case 0x93:
            match ret_code[1]:
                case 0x02:
                    ret_string = "Invalid MAC"

        case 0x94:
            match ret_code[1]:
                case 0x01:
                    ret_string = "The amount is insufficient"
                case 0x03:
                    ret_string = "Key indexes are not supported"

        case 0x90:
            if ret_code[1] == 0:
                ret_string = "Operation Successful"

    if console_print:
        print(f"[{color('=', fg='yellow')}] SW1_SW2 <= {bytes_to_hexstr(ret_code)} => {ret_string}")

    return ret_string

def TLVanalysis(TLV, tagLen=1):
    """Parse a simple TLV structure into a dict.

    Expects 1-byte tag by default; set tagLen=2 for 2-byte tags.
    Returns dict mapping tag bytes -> value bytes, or 'error' on failure.
    """
    sum = 0
    TLVdict = {}
    while (1):
        try:
            tag = TLV[sum:sum + tagLen]
            try:
                length = TLV[sum + tagLen]
            except:
                TLVdict[tag] = b'None'
                break
            value = TLV[sum + tagLen + 1:sum + tagLen + 1 + length]
            TLVdata = {'tag': tag, 'length': length, 'value': value}
            TLVdict[tag] = value
            sum = sum + length + tagLen + 1
            if sum >= len(TLV):
                break
        except:
            return 'error'
    return TLVdict
    
def TLVcreate(tag, value):
    """Create TLV bytes (1-byte length) from tag and value."""
    len = len(value)
    TLVdata = tag + bytes([len]) + value
    return TLVdata

class FMCOS():
    """High-level FMCOS card API with MAC/encryption support and helpers.

    Wraps a hardware connection (PM3, PN532, pyscard) to send APDUs and
    provides helpers for TLV parsing, MACing, and various FMCOS commands.
    """
    def __init__(self, hw_conn, fmcos_debug):
        self.hw_conn = hw_conn
        self.simulation_status = False
        self.fmcos_debug = fmcos_debug

    def nfcFindCard(self):
        return self.hw_conn.nfcFindCard()

    def nfcGetRecData(self):
        return self.hw_conn.nfcGetRecData()

    def simulation(self, enabled):
        self.simulation_status = enabled

    def is_success(self, ret_code):
        """Return True if response ends with SW=0x9000."""
        if ret_code[-2:] != b"\x90\x00":
            return False
        return True

    def data_xor(self, src, dst):
        """XOR two 8-byte blocks and return the result."""
        out_buf = b""
        for i in range(8):
            out_buf += (src[i] ^ dst[i]).to_bytes()
        return out_buf

    #https://github.com/Legrandin/pycryptodome/issues/297#issuecomment-500383674
    def make_cipher(self, key):
        """Return DES/3DES ECB cipher matching key size and duplication rules.

    Key interpretation:
    - 8 bytes -> DES
    - 16 bytes -> if halves equal, DES; else 2-key 3DES
    - 24 bytes -> reduce to DES or 2-key 3DES when halves repeat, else 3DES
        """
        cipher = None
        if len(key) == 8:
            cipher = DES.new(key, DES.MODE_ECB)
        elif len(key) == 16:
            if key[:8] == key[8:16]:
                cipher = DES.new(key[:8], DES.MODE_ECB)
            else:
                cipher = DES3.new(key, DES3.MODE_ECB)
        else:
            if key[:8] == key[8:16] and key[-8:] == key[8:16]:
                cipher = DES.new(key[:8], DES.MODE_ECB)
            elif key[:8] == key[8:16]:
                cipher = DES3.new(key[8:], DES3.MODE_ECB)
            elif key[-8:] == key[8:16]:
                cipher = DES3.new(key[:-8], DES3.MODE_ECB)
            else:
                cipher = DES3.new(key, DES3.MODE_ECB)
        return cipher

    def encrypt(self, data, key):
        """ISO7816-pad and encrypt with the cipher returned by make_cipher."""
        cipher = self.make_cipher(key)
        new_buf = pad(data, cipher.block_size, style='iso7816')
        return cipher.encrypt(new_buf)

    def decrypt(self, data, key):
        """Decrypt and unpad with ISO7816 style."""
        cipher = self.make_cipher(key)
        new_buf = cipher.decrypt(data)
        return unpad(new_buf, cipher.block_size, style='iso7816')

    def fmcos_des_mac(self, buf, key, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00", ret_cnt=4):
        """Compute single-DES CBC-MAC over ISO7816-padded data; return first ret_cnt bytes."""
        new_buf = pad(buf, DES.block_size, style='iso7816')
        x = len(new_buf) // 8
        val = iv
        DESECB = DES.new(key, DES.MODE_ECB)

        for i in range(x):
            xor_data = self.data_xor(val, new_buf[(i*8):(i*8)+8])
            val = DESECB.encrypt(xor_data)

        return val[:ret_cnt]

    def fmcos_3des_mac(self, buf, key, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00", ret_cnt=4):
        """Compute 3DES CBC-MAC (DES-L, DES-R, DES-L) variant; return first ret_cnt bytes."""
        key_l = key[:8]
        key_r = key[8:]
        DESECB_L = DES.new(key_l, DES.MODE_ECB)
        DESECB_R = DES.new(key_r, DES.MODE_ECB)

        val = self.fmcos_des_mac(buf=buf, key=key_l, iv=iv, ret_cnt=8)
        val = DESECB_R.decrypt(val)
        val = DESECB_L.encrypt(val)

        return val[:ret_cnt]

    def fmcos_packet_mac(self, cla, ins, p1, p2, data, iv, key):
        """Build MAC for APDU header + optional data as per FMCOS spec."""
        if key == None:
            raise ValueError(f"MAC calculations require a key")

        full_mac_data = b""
        full_mac_data += cla.to_bytes()
        full_mac_data += ins.to_bytes()
        full_mac_data += p1.to_bytes()
        full_mac_data += p2.to_bytes()
        if data == None:
            lc = 4
            full_mac_data += lc.to_bytes()
        else:
            full_mac_data += ( (len(data)+4) & 0xff ).to_bytes()   #LC
            full_mac_data += data
        #Calculate MAC
        if len(key) == 8:
            ret_mac = self.fmcos_des_mac(buf=full_mac_data, iv=iv, key=key)
        else:
            ret_mac = self.fmcos_3des_mac(buf=full_mac_data, iv=iv, key=key)
        return ret_mac

    def cmd_select(self, fileID=None, name=None):
        """SELECT by fileID (short File ID) or name (AID)."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if fileID == None and name == None:
            raise ValueError("fileID or name cannot be empty")

        cla = 0x00
        ins = 0xa4
        p2 = 0x00

        if name:
            p1 = 0x04
            ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=name)
        else:
            p1 = 0x00
            fileIDlist = strToint16(fileID)
            ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=fileIDlist,le=0x00)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] SELECT => {bytes_to_hexstr(ret)}\n")
            if ret[-2:] == b"\x90\x00":
                self.parse_tlv(ret)

        return ret

    def cmd_get_challenge(self, challenge_length=4):
        """GET CHALLENGE (4 or 8 bytes)."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if challenge_length != 4 and challenge_length != 8:
            raise ValueError("Invalid challenge_length size, only 4 or 8 accepted")

        if self.simulation_status:
            return b"\xff\xff\xff\xff\xff\xff\xff\xff\x90\x00"

        cla = 0x00
        ins = 0x84
        p1 = 0
        p2 = 0
        chlg = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,le=challenge_length)
        if challenge_length == 4:
            chlg = chlg + b'\x00\x00\x00\x00'

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] GET_CHALLENGE => {bytes_to_hexstr(chlg)}\n")

        return chlg

    def cmd_erase_df(self):
        """ERASE DF command."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x80
        ins = 0x0e
        p1 = 0
        p2 = 0
           
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] ERASE_DF => {bytes_to_hexstr(ret)}\n")

        return ret

    def cmd_external_authenticate(self, key_id, key=b'\xff\xff\xff\xff\xff\xff\xff\xff'):
        """EXTERNAL AUTHENTICATE using single/2-key/3-key DES depending on key length."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if len(key) != 8 and len(key) != 16:
            raise ValueError("Invalid key size, only 8 or 16 bytes accepted")

        chlg = self.cmd_get_challenge(8)
        if chlg[-2:] != b"\x90\x00":
            raise ValueError(f"GET_CHALLENGE was not successful")

        cla = 0x00
        ins = 0x82
        p1 = 0x00
        p2 = key_id

        chlg = chlg[:-2]    #Remove SW1_SW2
        cipher = self.make_cipher(key)
        chlg_resp =  cipher.encrypt(chlg)

        ret  = self.sendCommand(cla=cla, ins=ins, p1=p1, p2=p2, Data=chlg_resp)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] EXTERNAL_AUTHENTICATE => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_internal_authenticate(self, p1, p2, data):
        """INTERNAL AUTHENTICATE passthrough."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x00
        ins = 0x88

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] INTERNAL_AUTHENTICATE => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_create_directory(self, file_id, file_space, create_permissions, erase_permission, app_id, df_name):
        """CREATE FILE for MF/DF directory objects."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x80
        ins = 0xe0
        p1 = (file_id & 0xFF00) >> 8
        p2 = file_id & 0xFF

        data = b""
        data += CPUFileType.MFDF.value.to_bytes()
        data += struct.pack(">H", file_space)
        data += create_permissions.to_bytes()
        data += erase_permission.to_bytes()
        data += app_id.to_bytes()
        data += b"\xff\xff" #Not used parameters
        data += df_name

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] CREATE_DIRECTORY => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_create_edep(self, balance_type, usage_rights, loop_file_id):
        """CREATE WALLET (EDEP) for passbook/wallet balances."""
        if self.fmcos_debug: print(f"Calling : {sys._getframe(0).f_code.co_name}({balance_type.name})")

        cla = 0x80
        ins = 0xe0
        file_id = balance_type.value
        p1 = (file_id & 0xFF00) >> 8
        p2 = file_id & 0xFF

        data = b""
        data += CPUFileType.Wallet.value.to_bytes()
        data += b"\x02\x08"
        data += usage_rights.to_bytes()
        data += b"\x00\xff"
        data += loop_file_id.to_bytes()

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] CREATE_WALLET => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_create_keyfile(self, file_id, file_space, df_sid, key_permission):
        """CREATE KEYFILE with space and permissions."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x80
        ins = 0xe0
        p1 = (file_id & 0xFF00) >> 8
        p2 = file_id & 0xFF

        data = b""
        data += CPUFileType.Keyfile.value.to_bytes()
        data += struct.pack(">H", file_space)
        data += df_sid.to_bytes()
        data += key_permission.to_bytes()
        data += b"\xff\xff" #Not used parameters

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] CREATE_KEYFILE => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_create_file(self, file_id, file_type, file_size, read_perm, write_perm, access_rights, protection:Protection = None):
        """CREATE BINARY/RECORD/LOOP files with optional protection flags."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}({file_type.name})")

        cla = 0x80
        ins = 0xe0
        p1 = (file_id & 0xFF00) >> 8
        p2 = file_id & 0xFF

        full_file_type = file_type.value
        if protection != None:
            full_file_type |= protection.value

        data = b""
        data += full_file_type.to_bytes()
        data += struct.pack(">H", file_size)
        data += read_perm.to_bytes()
        data += write_perm.to_bytes()
        data += b"\xff"
        data += access_rights.to_bytes()

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] CREATE_FILE => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_write_key(self, key_add_update, key_id, key_type, usage_rights, key, change_rights=None, key_version=None, algo_id=None, \
                      followup_status=None, error_counter=None, extauth_key=None, protection:Protection = None):
        """WRITE KEY variants for multiple key types; supports MAC/enc line protection."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}({key_type.name})")

        cla = 0x80
        ins = 0xD4
        if isinstance(key_add_update, KeyType):
            p1 = key_add_update.value
        else:
            p1 = key_add_update

        p2 = key_id

        full_key_type = key_type.value
        if protection:
            if extauth_key == None:
                raise ValueError("extauth_key is required for MAC/encryption")
            full_key_type |= protection.value
            cla |= 0x04

        data = b""
        data += full_key_type.to_bytes()

        match key_type:
            case KeyType.InternalKey | KeyType.OverdrawLimitKey | KeyType.DebitKey | KeyType.PurchaseKey \
                | KeyType.CreditKey | KeyType.DESEncrypt | KeyType.DESDecrypt | KeyType.DESMAC:
                if key_version == None or algo_id == None:
                    raise ValueError(f"Key type {key_type.name} requires key_version and algo_id to be presented")

                data += usage_rights.to_bytes()
                data += change_rights.to_bytes()
                data += key_version.to_bytes()
                data += algo_id.to_bytes()
                
            case KeyType.ExternalAuthenticationKey | KeyType.PinKey:
                if followup_status == None or error_counter == None:
                    raise ValueError(f"Key type {key_type.name} requires followup_status and error_counter to be presented")

                data += usage_rights.to_bytes()

                if key_type == KeyType.PinKey:
                    data += b"\xef"
                else:
                    if change_rights == None:
                        raise ValueError(f"Key type {key_type.name} requires change_rights to be presented")

                    data += change_rights.to_bytes()

                data += followup_status.to_bytes()
                data += error_counter.to_bytes()

            case KeyType.UnlockPinKey | KeyType.FileLineProtectionKey | KeyType.ChangePinKey:
                if error_counter == None:
                    raise ValueError(f"Key type {key_type.name} requires error_counter to be presented")

                data += usage_rights.to_bytes()
                data += change_rights.to_bytes()
                data += b"\xff"
                data += error_counter.to_bytes()

            case _:
                raise ValueError(f"Key type not implemented: {key_type}")

        data += key

        if protection == Protection.LineProtectEncrypt:
            data = len(data).to_bytes() + data
            data = self.encrypt(data=data, key=extauth_key)

        if protection:
            chlg_iv = self.cmd_get_challenge(8)
            data += self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=data, iv=chlg_iv, key=extauth_key)

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] WRITE_KEY => {bytes_to_hexstr(ret)}\n")
        return ret
        
    def _cmd_update_bin_rec(self, ins, p1, p2, data, key=None, protection:Protection = None):
        """Common helper for UPDATE BINARY/RECORD with optional line protection."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name} ({protection=})")

        #Need to account for padding + mac
        if len(data) > 245:
            raise ValueError("data MAX length can only be 245")

        cla = 0
        if protection:
            if key == None:
                raise ValueError("key is required for MAC/encryption")
            cla |= 0x04
            le=4
        ins = ins

        data_bin = b""
        data_bin += data

        if protection == Protection.LineProtectEncrypt:
            data_bin = len(data_bin).to_bytes() + data_bin
            data_bin = self.encrypt(data=data_bin, key=key)

        if protection:
            chlg_iv = self.cmd_get_challenge(8)
            data_bin += self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=data_bin, iv=chlg_iv, key=key)

        ret = self.sendCommand(cla,ins,p1,p2,Data=data_bin)
        return ret

    def cmd_update_binary(self, p1, p2, data, key=None, protection:Protection = None):
        """UPDATE BINARY wrapper."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        ins = 0xd6
        ret = self._cmd_update_bin_rec(ins=ins, p1=p1, p2=p2, data=data, key=key, protection=protection)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] UPDATE_BINARY => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_update_record(self, record_number, file_id, data, key=None, use_tlv=False, protection:Protection = None):
        """UPDATE RECORD wrapper; can wrap data in a simple TLV (tag 0xF7)."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        ins = 0xdc
        p1 = record_number
        p2 = ( (file_id & 0x1f) << 3 ) | 4

        if use_tlv:
            data = b"\xF7" + len(data).to_bytes() + data

        ret = self._cmd_update_bin_rec(ins=ins, p1=p1, p2=p2, data=data, key=key, protection=protection)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] UPDATE_RECORD => {bytes_to_hexstr(ret)}\n")
        return ret

    def _cmd_read_bin_rec(self, ins, p1, p2, read_length=1, key=None, protection:Protection = None):
        """Common helper for READ BINARY/RECORD with optional MAC validation and decrypt."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if read_length > 0xff:
            raise ValueError("read_length MAX length can only be 255")

        cla = 0x00
        if protection:
            if key == None:
                raise ValueError("key is required for MAC/encryption")
            cla |= 0x04

        data = None
        if protection:
            chlg_iv = self.cmd_get_challenge(8)
            data = self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=data, iv=chlg_iv, key=key)

        ret = self.sendCommand(cla,ins,p1,p2,Data=data, le=read_length)
        assert ret[-2:] == b"\x90\x00", f"Card did not return success"

        if protection: #Validate MAC
            ret_mac = ret[-6:-2]
            ret_msg = ret[:-6]

            #Calculate msg MAC
            if len(key) == 8:
                calc_mac = self.fmcos_des_mac(buf=ret_msg, iv=chlg_iv, key=key)
            else:
                calc_mac = self.fmcos_3des_mac(buf=ret_msg, iv=chlg_iv, key=key)

            if self.fmcos_debug:
                print(f"[{color('=', fg='yellow')}] RET_MSG => {bytes_to_hexstr(ret_msg)}")
                print(f"[{color('=', fg='yellow')}] MAC_MSG => {bytes_to_hexstr(ret_mac)} <> MAC_CALC => {bytes_to_hexstr(calc_mac)}")
                assert calc_mac == ret_mac, f"MAC validation failed"
                print(f"[{color('+', fg='green')}] MAC validation successful")

        if protection == Protection.LineProtectEncrypt:
            ret = self.decrypt(data=ret_msg, key=key)[1:] #First byte is the size
            ret += b"\x90\x00"  #Append a success SW1_SW2

        return ret

    def cmd_read_binary(self, p1, p2, read_length=1, key=None, protection:Protection = None):
        """READ BINARY wrapper."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        ins = 0xB0
        ret = self._cmd_read_bin_rec(ins=ins, p1=p1, p2=p2, read_length=read_length, key=key, protection=protection)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] READ_BINARY => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_read_record(self, record_number, file_id, read_length=0, has_tlv=False, key=None, protection:Protection = None):
        """READ RECORD wrapper; optional TLV unwrapping (tag 0xF7)."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if has_tlv:
            read_length += 2

        ins = 0xB2
        p1 = record_number
        p2 = ( (file_id & 0x1f) << 3 ) | 4
        ret = self._cmd_read_bin_rec(ins=ins, p1=p1, p2=p2, read_length=read_length, key=key, protection=protection)

        if has_tlv:
            assert ret[0] == 0xf7, f"TLV Tag incorrect"
            ret = ret[2:]

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] READ_RECORD => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_append_record(self, file_id, data, key=None, use_tlv=False, protection:Protection = None):
        """APPEND RECORD, optionally TLV-wrapped."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if use_tlv:
            data = b"\xF7" + len(data).to_bytes() + data

        ins = 0xe2
        p1 = 0
        p2 = ( (file_id & 0x1f) << 3 ) | 4
        ret = self._cmd_update_bin_rec(ins=ins, p1=p1, p2=p2, data=data, key=key, protection=protection)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] APPEND_RECORD => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_get_balance(self, balance_type):
        """GET BALANCE for passbook or wallet."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x80
        ins = 0x5c
        p1 = 0x00
        p2 = balance_type.value
        
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2, le=4)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] GET_BALANCE => {bytes_to_hexstr(ret)}\n")
        return ret

    def cmd_verify_pin(self, key_id, pin_code):
        """VERIFY PIN given key slot and PIN bytes."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        cla = 0x00
        ins = 0x20
        p1 = 0x00
        p2 = key_id
        
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=pin_code)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] VERIFY_PIN => {bytes_to_hexstr(ret)}\n")
        return ret

    #Key is a credit or debit key
    def _transfer(self, balance_type, key_id, amount, terminal_id, crde_key, internal_key, transfer_type):
        """Two-step credit/debit flow with MAC verification and TAC validation."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if self.simulation_status:  #Simulation needs work here
            return b"\x90\x00"

        if len(crde_key) != 16:
            raise ValueError("crde_key needs to be 16 bytes")

        if transfer_type == 0 and len(internal_key) != 16:
            raise ValueError("internal_key needs to be 16 bytes")

        p1 = transfer_type
        p2 = balance_type.value

        if transfer_type == 0x00:
            p1_v2 = 0x00
            ins_v2 = 0x52
            transaction_type = balance_type.value
        elif transfer_type == 0x05:
            p1_v2 = 0x03
            ins_v2 = 0x54
            transaction_type = 0x03

        packed_amount = struct.pack(">I", amount)

        data = b""
        data += key_id.to_bytes()
        data += packed_amount
        data += terminal_id

        cla = 0x80
        ins = 0x50
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data,le=0x10)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] TRANSFER_PT1 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("First part of transfer failed...")

        old_balance = struct.unpack(">I", ret[:4])[0]
        online_transaction_serial = ret[4:6]
        key_version = ret[6:7]
        algo_id = ret[7:8]
        random_1 = ret[8:12]
        mac_1 = ret[12:16]

        #Compute the process key
        pk_buffer = random_1 + online_transaction_serial
        process_key = self.encrypt(data=pk_buffer, key=crde_key)

        #Verify MAC_1 (Old Balance)(amount)(balance_type)(terminal_id)
        mac_verify_buffer = ret[:4] + packed_amount + transaction_type.to_bytes() + terminal_id
        mac1_calculated = self.fmcos_des_mac(mac_verify_buffer, process_key)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] mac_verify_buffer => {bytes_to_hexstr(mac_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] Process Key => {bytes_to_hexstr(process_key)}")
            print(f"[{color('=', fg='yellow')}] mac_1 => {bytes_to_hexstr(mac_1)} <> mac1_calculated => {bytes_to_hexstr(mac1_calculated)}")

        assert mac1_calculated == mac_1, "MAC_1 does not match"

        #Compute MAC2
        now = datetime.datetime.now()
        transaction_date = bytes.fromhex(now.strftime("%Y%m%d"))
        transaction_time = bytes.fromhex(now.strftime("%H%M%S"))
        mac2_verify_buffer = packed_amount + transaction_type.to_bytes() + terminal_id + transaction_date + transaction_time
        mac2_calculated = self.fmcos_des_mac(mac2_verify_buffer, process_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] mac2_verify_buffer => {bytes_to_hexstr(mac2_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] mac2_calculated => {bytes_to_hexstr(mac2_calculated)}")

        data = b""
        data += transaction_date
        data += transaction_time
        data += mac2_calculated

        cla = 0x80
        p2 = 0x00
        ret = self.sendCommand(cla=cla,ins=ins_v2,p1=p1_v2,p2=p2,Data=data,le=0x4)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] TRANSFER_PT2 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("Second part of transfer failed...")

        #Calculate & Validate Transaction Verification Code (TAC) / MAC3
        CARD_TAC = ret[:4]
        if transfer_type == 0x00:
            new_balance = old_balance + amount
            tac_key = self.data_xor(internal_key[0:8], internal_key[8:])
        elif transfer_type == 0x05:
            new_balance = old_balance - amount
            tac_key = process_key

        tac_verify_buffer = struct.pack(">I", new_balance) + online_transaction_serial + mac2_verify_buffer
        tac_calculated = self.fmcos_des_mac(tac_verify_buffer, tac_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] tac_key => {bytes_to_hexstr(tac_key)}")
            print(f"[{color('=', fg='yellow')}] tac_verify_buffer => {bytes_to_hexstr(tac_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] CARD_TAC => {bytes_to_hexstr(CARD_TAC)} <> tac_calculated => {bytes_to_hexstr(tac_calculated)}\n")

        assert CARD_TAC == tac_calculated, "TAC does not match"
        
        return b"\x90\x00"

    def cmd_add_credit(self, balance_type, key_id, amount, terminal_id, credit_key, internal_key):
        """Add credit to wallet/passbook."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        return self._transfer(balance_type=balance_type, key_id=key_id, amount=amount, terminal_id=terminal_id, \
                            crde_key=credit_key, internal_key=internal_key, transfer_type=0x00)

    def cmd_online_transfer(self, key_id, amount, terminal_id, debit_key, internal_key, transaction_serial=None):
        """Online transfer (debit) to passbook."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        return self._transfer(balance_type=BalanceType.Passbook, key_id=key_id, amount=amount, terminal_id=terminal_id, \
                            crde_key=debit_key, internal_key=internal_key, transfer_type=0x05)

    def cmd_cash_withdraw(self, key_id, amount, terminal_id, purchase_key, internal_key, transaction_serial=None):
        """Cash withdrawal flow using purchase key."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        return self._transaction(balance_type=BalanceType.Passbook, key_id=key_id, amount=amount, terminal_id=terminal_id,\
                                    transaction_type_id=0x04, purchase_key=purchase_key, internal_key=internal_key, transaction_serial=None)

    def cmd_purchase_passbook(self, key_id, amount, terminal_id, purchase_key, internal_key, transaction_serial=None):
        """Purchase using passbook balance."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        return self._transaction(balance_type=BalanceType.Passbook, key_id=key_id, amount=amount, terminal_id=terminal_id,\
                                    transaction_type_id=0x05, purchase_key=purchase_key, internal_key=internal_key, transaction_serial=None)

    def cmd_purchase_wallet(self, key_id, amount, terminal_id, purchase_key, internal_key, transaction_serial=None):
        """Purchase using wallet balance."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        return self._transaction(balance_type=BalanceType.Wallet, key_id=key_id, amount=amount, terminal_id=terminal_id,\
                                    transaction_type_id=0x06, purchase_key=purchase_key, internal_key=internal_key, transaction_serial=None)

    def _transaction(self, balance_type:BalanceType, key_id, amount, transaction_type_id, terminal_id, purchase_key, internal_key, transaction_serial=None):
        """Two-step purchase/cash-withdrawal flow with MACs and TAC validation."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")

        if self.simulation_status:  #Simulation needs work here
            return b"\x90\x00"

        if len(purchase_key) != 16:
            raise ValueError("purchase_key needs to be 16 bytes")

        if len(internal_key) != 16:
            raise ValueError("internal_key needs to be 16 bytes")

        if transaction_type_id == 0x05 or transaction_type_id == 0x06:  #Purchase with passbook/wallet
            p1 = 0x01
            p2 = balance_type.value
        elif transaction_type_id == 0x09:   #CAPP Purchase
            p1 = 0x03
            p2 = 0x02
        elif transaction_type_id == 0x04: #Cash withdrawal
            p1 = 0x02
            p2 = BalanceType.Passbook.value
        else:
            raise ValueError(f"Unknown {transaction_type_id=}")

        packed_amount = struct.pack(">I", amount)

        data = b""
        data += key_id.to_bytes()
        data += packed_amount
        data += terminal_id

        cla = 0x80
        ins = 0x50
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data,le=0x0F)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] TRANSACTION_PT1 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("First part of transaction failed...")

        old_balance = struct.unpack(">I", ret[:4])[0]
        offline_transaction_serial = ret[4:6]
        overdraft_limit = ret[6:9]
        key_version = ret[9:10]
        algo_id = ret[10:11]
        random_1 = ret[11:15]

        #Generate a random serial number if one is not supplied
        if transaction_serial == None:
            transaction_serial = os.urandom(4)
        else:
            if len(transaction_serial) != 4:
                raise ValueError("transaction_serial needs to be 4 bytes")

        #Compute the process key
        pk_buffer = random_1 + offline_transaction_serial + transaction_serial[-2:]
        process_key = self.encrypt(data=pk_buffer, key=purchase_key)
        process_key = process_key[:8]

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] pk_buffer => {bytes_to_hexstr(pk_buffer)}")
            print(f"[{color('=', fg='yellow')}] Process Key => {bytes_to_hexstr(process_key)}")
            print(f"[{color('=', fg='yellow')}] Transaction Serial => {bytes_to_hexstr(transaction_serial)}")

        #Compute MAC1
        now = datetime.datetime.now()
        transaction_date = bytes.fromhex(now.strftime("%Y%m%d"))
        transaction_time = bytes.fromhex(now.strftime("%H%M%S"))

        mac1_verify_buffer = packed_amount + transaction_type_id.to_bytes() + terminal_id + transaction_date + transaction_time
        mac1_calculated = self.fmcos_des_mac(buf=mac1_verify_buffer, key=process_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] mac1_verify_buffer => {bytes_to_hexstr(mac1_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] mac1_calculated => {bytes_to_hexstr(mac1_calculated)}")

        data = b""
        data += transaction_serial
        data += transaction_date
        data += transaction_time
        data += mac1_calculated

        cla = 0x80
        ins = 0x54
        p1 = 0x01
        p2 = 0x00
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data,le=0x8)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] TRANSACTION_PT2 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("Second part of transaction failed...")

        #Calculate & Validate Transaction Verification Code (TAC)
        CARD_TAC = ret[:4]
        mac2_card = ret[4:8]
        tac_key = self.data_xor(internal_key[0:8], internal_key[8:])

        tac_verify_buffer = packed_amount + transaction_type_id.to_bytes() + terminal_id + transaction_serial + transaction_date + transaction_time
        tac_calculated = self.fmcos_des_mac(tac_verify_buffer, tac_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] tac_key => {bytes_to_hexstr(tac_key)}")
            print(f"[{color('=', fg='yellow')}] tac_verify_buffer => {bytes_to_hexstr(tac_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] CARD_TAC => {bytes_to_hexstr(CARD_TAC)} <> tac_calculated => {bytes_to_hexstr(tac_calculated)}\n")

        assert CARD_TAC == tac_calculated, "TAC does not match"

        return b"\x90\x00"

    def cmd_update_overdraft_limit(self, key_id, new_overdraft_limit, terminal_id, overdraft_key, internal_key, transaction_serial=None):
        """Update overdraft limit with MAC verification and TAC validation."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        if len(overdraft_key) != 16:
            raise ValueError("overdraft_key needs to be 16 bytes")

        if len(internal_key) != 16:
            raise ValueError("internal_key needs to be 16 bytes")

        p1 = 0x04
        p2 = BalanceType.Passbook.value
        transaction_type = 0x07

        packed_new_overdraft_limit = struct.pack(">I", new_overdraft_limit)

        data = b""
        data += key_id.to_bytes()
        data += terminal_id

        cla = 0x80
        ins = 0x50
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data,le=0x13)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] OVERDRAFT_PT1 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("First part of overdraft failed...")

        old_balance = ret[:4]
        online_transaction_serial = ret[4:6]
        old_overdraft_limit = ret[6:9]
        key_version = ret[9:10]
        algo_id = ret[10:11]
        random_1 = ret[11:15]
        card_mac_1 = ret[15:19]

        #Compute the process key
        pk_buffer = random_1 + online_transaction_serial
        process_key = self.encrypt(data=pk_buffer, key=overdraft_key)
        process_key = process_key[:8]

        mac1_verify_buffer = old_balance + old_overdraft_limit + transaction_type.to_bytes() + terminal_id
        mac1_calculated = self.fmcos_des_mac(buf=mac1_verify_buffer, key=process_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] mac1_verify_buffer => {bytes_to_hexstr(mac1_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] mac1_calculated => {bytes_to_hexstr(mac1_calculated)}")
            print(f"[{color('=', fg='yellow')}] card_mac_1 => {bytes_to_hexstr(card_mac_1)} <> mac1_calculated => {bytes_to_hexstr(mac1_calculated)}\n")

        assert mac1_calculated == card_mac_1, "MAC_1 does not match"

        #Calculate MAC2
        now = datetime.datetime.now()
        transaction_date = bytes.fromhex(now.strftime("%Y%m%d"))
        transaction_time = bytes.fromhex(now.strftime("%H%M%S"))

        mac2_verify_buffer = struct.pack(">I", new_overdraft_limit)[1:] + transaction_type.to_bytes() + terminal_id + transaction_date + transaction_time
        mac2_calculated = self.fmcos_des_mac(buf=mac2_verify_buffer, key=process_key)

        data = b""
        data += struct.pack(">I", new_overdraft_limit)[1:]
        data += transaction_date
        data += transaction_time
        data += mac2_calculated

        cla = 0x80
        ins = 0x58
        p1 = 0x00
        p2 = 0x00
        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data,le=0x4)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] OVERDRAFT_PT2 => {bytes_to_hexstr(ret)}\n")

        if not self.is_success(ret):
            raise ValueError("Second part of overdraft failed...")

        #Calculate & Validate Transaction Verification Code (TAC)
        CARD_TAC = ret[:4]

        tac_key = self.data_xor(internal_key[0:8], internal_key[8:])
        new_balance = struct.unpack(">I", old_balance)[0] + new_overdraft_limit

        tac_verify_buffer = struct.pack(">I", new_balance) + online_transaction_serial + mac2_verify_buffer
        tac_calculated = self.fmcos_des_mac(tac_verify_buffer, tac_key)

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] tac_key => {bytes_to_hexstr(tac_key)}")
            print(f"[{color('=', fg='yellow')}] tac_verify_buffer => {bytes_to_hexstr(tac_verify_buffer)}")
            print(f"[{color('=', fg='yellow')}] CARD_TAC => {bytes_to_hexstr(CARD_TAC)} <> tac_calculated => {bytes_to_hexstr(tac_calculated)}\n")

        assert CARD_TAC == tac_calculated, "TAC does not match"

        return b"\x90\x00"

    def cmd_card_block(self, line_key):
        """Block entire card using line-protection MAC."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        cla = 0x84
        ins = 0x16
        p1 = 0x00
        p2 = 0x00

        chlg_iv = self.cmd_get_challenge(8)
        data = self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=None, iv=chlg_iv, key=line_key)

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] CARD_BLOCK => {bytes_to_hexstr(ret)}\n")

        return ret

    def cmd_app_block(self, block_type:ApplicationBlock, line_key):
        """Block application (temporary or permanent)."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        cla = 0x84
        ins = 0x1e
        p1 = 0x00
        p2 = block_type.value

        chlg_iv = self.cmd_get_challenge(8)
        data = self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=None, iv=chlg_iv, key=line_key)

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] APPLICATION_BLOCK => {bytes_to_hexstr(ret)}\n")

        return ret

    def cmd_app_unblock(self, line_key):
        """Unblock application using line-protection MAC."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        cla = 0x84
        ins = 0x18
        p1 = 0x00
        p2 = 0x00

        chlg_iv = self.cmd_get_challenge(8)
        data = self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=None, iv=chlg_iv, key=line_key)

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] APPLICATION_UNBLOCK => {bytes_to_hexstr(ret)}\n")

        return ret

    def cmd_pin_unblock(self, key_id, pin_code, unlock_pin_key):
        """Unblock PIN by encrypting new PIN and appending MAC."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        cla = 0x84
        ins = 0x24
        p1 = key_id
        p2 = 0
        
        data = len(pin_code).to_bytes() + pin_code
        data = self.encrypt(data=data, key=unlock_pin_key)
        chlg_iv = self.cmd_get_challenge(8)
        data += self.fmcos_packet_mac(cla=cla, ins=ins, p1=p1, p2=p2, data=data, iv=chlg_iv, key=unlock_pin_key)

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] PIN_UNBLOCK => {bytes_to_hexstr(ret)}\n")
            
        return ret

    def cmd_pin_change(self, key_id, old_pin, new_pin):
        """Change PIN using old/new PIN with filler 0xFF separator."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        cla = 0x80
        ins = 0x5E
        p1 = 0x01
        p2 = key_id
        
        data = b""
        data += old_pin
        data += b"\xff"
        data += new_pin

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] PIN_UNBLOCK => {bytes_to_hexstr(ret)}\n")
            
        return ret

    def cmd_pin_reset(self, key_id, new_pin, change_pin_key):
        """Reset PIN with MAC generated from change-pin key halves xor."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        
        if len(change_pin_key) != 16:
            raise ValueError("change_pin_key needs to be 16 bytes")

        cla = 0x80
        ins = 0x5E
        p1 = 0x00
        p2 = key_id
        
        data = b""
        data += new_pin

        mac_key = self.data_xor(change_pin_key[0:8], change_pin_key[8:])
        mac_calculated = self.fmcos_des_mac(data, mac_key)
        data += mac_calculated

        ret = self.sendCommand(cla=cla,ins=ins,p1=p1,p2=p2,Data=data)
        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] PIN_UNBLOCK => {bytes_to_hexstr(ret)}\n")
            
        return ret

    def sendCommand(self, cla, ins, p1, p2, Data=None, le=None):
        """Compose and send an APDU via the underlying hardware connection."""
        context = [cla, ins, p1, p2]
        if Data != None:
            lc = len(Data)
            context = context + [lc] + list(Data)
        else:
            lc = None

        if le != None:
            context = context + [le]

        if lc == None and le == None:
            context = context + [0x00]

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] FMCOS => {bytes_to_hexstr(bytes(context))}" )

        if self.simulation_status:
            return b"\x90\x00"
        else:
            self.hw_conn.sendToNfc(context)
            recdata = self.fmcosGetRecData()
            return recdata

    def fmcosGetRecData(self):
        """Fetch last NFC data and decode status for logs; return raw bytes."""
        nfcdata = self.hw_conn.nfcGetRecData()

        if self.fmcos_debug:
            print(f"[{color('=', fg='yellow')}] FMCOS <= " + bytes_to_hexstr(nfcdata) )

        parse_return_code(nfcdata[-2:], self.fmcos_debug)

        return nfcdata

    def parse_tlv(self, tlv_data):
        """Parse and print basic SELECT response TLV tree; return DFName if present."""
        if self.fmcos_debug: print(f"[{color('+', fg='green')}] Calling : {sys._getframe(0).f_code.co_name}")
        SW1_SW2 = tlv_data[-2:]
        answer = tlv_data[:-2]

        if SW1_SW2 == b"\x90\x00":
            try:
                TLVdict = TLVanalysis(answer)
                TLVdict1 = TLVanalysis(TLVdict[b'\x6f'])

                #if self.fmcos_debug:
                #    print(f"[{color('=', fg='yellow')}] {TLVdict=}")
                #    print(f"[{color('=', fg='yellow')}] {TLVdict1=}")

                DFName = TLVdict1[b'\x84']
                try:
                    ctrlMsg = TLVdict1[b'\xa5']
                    try:
                        ctrlMsg = TLVanalysis(ctrlMsg)[b'\x88']
                    except:
                        try:
                            ctrlMsg = TLVanalysis(ctrlMsg, tagLen=2)[b'\x9f\x0c']
                        except:
                            ctrlMsg = b'noCtrlMsg'

                except:
                    ctrlMsg = b'noCtrlMsg'

                if self.fmcos_debug:
                    if ctrlMsg != b"noCtrlMsg":
                        print(f"[{color('=', fg='yellow')}] parse_tlv(ctrlMsg) => {ctrlMsg}")
                    print(f"[{color('=', fg='yellow')}] parse_tlv(DFName) => {DFName}\n")

                return DFName
            except:
                if self.fmcos_debug:
                    print(f"[{color('=', fg='yellow')}] parse_tlv => {bytes_to_hexstr(answer)}\n")
                return answer
        else:
            raise ValueError("Failed to parse TLV")
