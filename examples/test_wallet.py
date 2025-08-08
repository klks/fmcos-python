"""Wallet / passbook operations interactive test.

Demonstrates setting up keys, balances (wallet + passbook), then performing
credit, purchase, debit, overdraft, and PIN life-cycle operations.
Run and type commands such as: setup, add_money, spend_wallet, get_balance.
"""
import sys
import os
import traceback
import struct
from Crypto.Cipher import DES  # type: ignore
from conn_pn532 import BRIDGE_PN532
from conn_pyscard import BRIDGE_PYSCARD
from fmcos import CPUFileType, KeyType, BalanceType, Protection, parse_return_code, FMCOS
from utils import bytes_to_hexstr, assert_success, assert_failure

# optional color support .. `pip install ansicolors`
try:
    from colors import color  # type: ignore
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

DEBUG_FMCOS = True
DEBUG_PN532 = False
DEBUG_ACR1518 = False

if __name__ == '__main__':
    #Keys used
    external_auth_key = b"\xf4\x9d\xc1\xba\x1b\x4d\xeb\x52\x64\x71\x86\xbc\x59\x10\x6c\x0d"
    internal_key = b"\x2b\x8a\x43\x87\x42\xc8\x51\x56\x6f\x02\xd8\x81\xb0\x9d\x58\xc0"
    line_protection_key = b"\x8a\x02\x19\x72\xbf\xec\x9d\x15\x2c\xa9\xeb\x82\xd7\xd1\x2c\x09"
    unlock_pin_key = b"\xd8\xf6\x0f\xa2\xd7\x91\xf3\xa6\x58\xd2\x7c\x05\x45\x82\x43\xed"
    change_pin_key = b"\xfb\x48\x7a\x6d\x1b\x7c\xbf\x1b\xf8\x4c\x66\x6b\x83\x38\x37\x6e"
    purchase_key = b"\xeb\x18\xce\x69\x86\xc8\x20\x97\x0e\x87\x62\x19\x05\x2c\xe0\xcf"
    credit_key = b"\xa9\xe6\xe1\x45\xf5\xdf\x09\x50\x0a\x58\xee\xf8\x57\x5d\x49\xdb"
    debit_key = b"\x97\xfb\x4e\xda\x4b\x52\x37\x03\x59\x46\xee\x62\xd3\x25\xd9\x09"
    overdraw_limit_key = b"\x94\xf6\x3c\x4f\xae\x5e\x49\x77\xd7\x49\x92\x8a\xd1\x2b\xc1\x28"
    pin_code = b"\x12\x34\x56"
    new_pin_code = b"\x13\x37\x13\x37"
    terminal_id = b"\x66\x66\x66\x66\x66\x66"

    int_enc = b"\xc4\x60\x8b\x78\x6a\xf1\x99\x23\x43\xe9\x1a\x07\x66\x70\xae\x7c"
    int_dec = b"\xb8\xd4\x19\x0c\x76\x85\x69\x01\xfc\x68\x6f\x36\xab\x9b\x1c\xe0"
    int_mac = b"\x46\xa3\xea\x8b\x25\x4e\xe2\x74\x9c\xc6\x81\x05\x0f\xd0\xdb\xcc"

    hw_conn = BRIDGE_PYSCARD(reader_string="ACS ACR1581 1S Dual Reader PICC 0", hw_debug=DEBUG_ACR1518)
    #hw_conn = BRIDGE_PN532(com_port="COM11", hw_debug=DEBUG_PN532)
    exam = FMCOS(hw_conn=hw_conn, fmcos_debug=DEBUG_FMCOS)
    while True:
        inp = input("> ")

        if len(inp) == 0:
            continue

        if inp == "exit":
            break

        elif inp.find('select') != -1:
            try:
                while (exam.nfcFindCard() == 'noCard'):
                    print('noCard')

                selections = inp.split(" ")[1:]

                for sel in selections:
                    exam.cmd_select(sel)
            except:
                print(traceback.format_exc())

        elif inp == "reset":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                ret = exam.cmd_erase_df()
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "setup":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                #Create an ADF
                ret = exam.cmd_create_directory(file_id=0x3f01, file_space=0x1500, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"walletTest")
                assert_success(exam, ret)

                #Switch to directory
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                #Create Keyfile
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0x200, df_sid=0x95, key_permission=0xf0)
                assert_success(exam, ret)

                #Keys for internal authenticate command
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.DESEncrypt, usage_rights=0xf0, \
                                    change_rights=0xf4, key_version=0x05, algo_id=0x98, key=int_enc)
                assert_success(exam, ret)
                
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.DESDecrypt, usage_rights=0xf0, \
                                    change_rights=0xf4, key_version=0x05, algo_id=0x98, key=int_dec)
                assert_success(exam, ret)
                
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.DESMAC, usage_rights=0xf0, \
                                    change_rights=0xf4, key_version=0x05, algo_id=0x98, key=int_mac)
                assert_success(exam, ret)

                #Create an InternalKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=internal_key)
                assert_success(exam, ret)

                #Create FileLineProtectionKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=line_protection_key)
                assert_success(exam, ret)

                #Create UnlockPinKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.UnlockPinKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=unlock_pin_key)
                assert_success(exam, ret)

                #Create ChangePinKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ChangePinKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=change_pin_key)
                assert_success(exam, ret)

                #create ExternalAuthenticationKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0x02, followup_status=0x44, error_counter=0x33, key=external_auth_key)
                assert_success(exam, ret)

                #Create PurchaseKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=purchase_key)
                assert_success(exam, ret)

                #Create CreditKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=credit_key)
                assert_success(exam, ret)

                #Create DebitKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.DebitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=debit_key)
                assert_success(exam, ret)

                #Create OverdrawLimitKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.OverdrawLimitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=overdraw_limit_key)
                assert_success(exam, ret)

                #Create PinKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                    followup_status=0x01, error_counter=0x33, key=pin_code)
                assert_success(exam, ret)

                #Create a LoopFile for transaction tracking
                ret = exam.cmd_create_file(file_id=0x0018, file_type=CPUFileType.LoopFile, file_size=0x0517, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
                assert_success(exam, ret)

                #Create a LoopFile for transaction tracking
                ret = exam.cmd_create_file(file_id=0x0019, file_type=CPUFileType.LoopFile, file_size=0x0517, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
                assert_success(exam, ret)

                #Create a wallet and link it to the loopfile
                ret = exam.cmd_create_edep(balance_type=BalanceType.Wallet, usage_rights=0xf0, loop_file_id=0x18)
                assert_success(exam, ret)

                #Create a passbook and link it to the loopfile
                ret = exam.cmd_create_edep(balance_type=BalanceType.Passbook, usage_rights=0xf0, loop_file_id=0x19)
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == "verify_pin":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            
            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "get_balance":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_get_balance(BalanceType.Wallet)
                assert_success(exam, ret)
                wallet_balance = struct.unpack(">I", ret[:4])[0]
                print(f"[{color('+', fg='green')}] Wallet Balance: {wallet_balance}\n\n")

                ret = exam.cmd_get_balance(BalanceType.Passbook)
                assert_success(exam, ret)
                passbook_balance = struct.unpack(">I", ret[:4])[0]
                print(f"[{color('+', fg='green')}] Passbook Balance: {passbook_balance}\n\n")

            except:
                print(traceback.format_exc())

        elif inp == "add_money":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                print("Add Money => Wallet")
                ret = exam.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=0, amount=1000, terminal_id=terminal_id, \
                                        credit_key=credit_key, internal_key=internal_key)
                assert_success(exam, ret)

                print("Add Money => Passbook")
                ret = exam.cmd_add_credit(balance_type=BalanceType.Passbook, key_id=0, amount=2000, terminal_id=terminal_id, \
                                        credit_key=credit_key, internal_key=internal_key)
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == "spend_wallet":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                print("Use Money => Wallet")
                ret = exam.cmd_purchase_wallet(key_id=0, amount=50, terminal_id=terminal_id, purchase_key=purchase_key, internal_key=internal_key)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "spend_passbook":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                print("Use Money => Passbook")
                ret = exam.cmd_purchase_passbook(key_id=0, amount=50, terminal_id=terminal_id, purchase_key=purchase_key, internal_key=internal_key)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "withdraw_money":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                print("Withdraw Money => Passbook")
                ret = exam.cmd_cash_withdraw(key_id=0, amount=100, terminal_id=terminal_id, purchase_key=purchase_key, internal_key=internal_key)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "pin_block":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                for _ in range(4):
                    ret = exam.cmd_verify_pin(key_id=0, pin_code=b"\x11\x22\x33\x44")

            except:
                print(traceback.format_exc())

        elif inp == "pin_unblock":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_pin_unblock(key_id=0, pin_code=pin_code, unlock_pin_key=unlock_pin_key)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "online_debit":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                print(f"Debit Money from Passbook to Online")
                ret = exam.cmd_online_transfer(key_id=0, amount=10, terminal_id=terminal_id, debit_key=debit_key, internal_key=None)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "update_overdraft":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_update_overdraft_limit(key_id=0, new_overdraft_limit=1000, terminal_id=terminal_id, overdraft_key=overdraw_limit_key, internal_key=internal_key)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "pin_change":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_pin_change(key_id=0, old_pin=pin_code, new_pin=new_pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=new_pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_pin_change(key_id=0, old_pin=new_pin_code, new_pin=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == "pin_reset":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"walletTest")
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_pin_reset(key_id=0, new_pin=new_pin_code, change_pin_key=change_pin_key)
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=new_pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_pin_change(key_id=0, old_pin=new_pin_code, new_pin=pin_code)
                assert_success(exam, ret)

                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())