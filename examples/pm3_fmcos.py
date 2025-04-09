#Place this file in your proxmarks pyscripts directory
import sys
import os
import argparse
import pm3
import struct

sys.path.append("D:\\LocalDev\\fmcos-python")   #Change this to fit
from conn_pm3 import BRIDGE_PM3
from fmcos import CPUFileType, KeyType, BalanceType, Protection, parse_return_code, FMCOS
from utils import bytes_to_hexstr, assert_success

author = "@klks"
script_ver = "1.0.0"

DEBUG_FMCOS = False
DEBUG_PM3 = True

pm3_conn = None
fmcos_conn = None

# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)
    
def waitForCard(max_tries=5):
    global pm3_conn, fmcos_conn

    tries = 0
    while (fmcos_conn.nfcFindCard() == 'noCard'):
        print('noCard')
        tries += 1
        if tries >= max_tries: break

    if tries >= max_tries:
        return False
    return True

def parseCli():
    """Parse the CLi arguments"""
    parser = argparse.ArgumentParser(description='FMCOS example script', exit_on_error=False)
    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    #Subcommand SELECT
    parser_select = subparsers.add_parser("select", help="SELECT command", exit_on_error=False)
    parser_select.add_argument('--id', dest="id", required=True, help="2 byte id (e.g: 3f00")

    parser_setup = subparsers.add_parser("setup", exit_on_error=False)
    parser_reset = subparsers.add_parser("reset", exit_on_error=False)
    parser_verify_pin = subparsers.add_parser("verify_pin", exit_on_error=False)
    parser_add_money = subparsers.add_parser("add_money", exit_on_error=False)
    parser_spend_money = subparsers.add_parser("spend_money", exit_on_error=False)
    parser_get_balance = subparsers.add_parser("get_balance", exit_on_error=False)

    args = parser.parse_args()
    return args

def select_wallet():
    global pm3_conn, fmcos_conn

    #Select by id or name
    #ret = fmcos_conn.cmd_select('3f01')
    #assert_success(fmcos_conn, ret)

    ret = fmcos_conn.cmd_select(name=b"walletTest")
    assert_success(fmcos_conn, ret)

def main():
    global pm3_conn, fmcos_conn

    p = pm3.pm3()  # console interface

    args = parseCli()
    if args == None: return

    pm3_conn = BRIDGE_PM3(pm3_debug=DEBUG_PM3, pm3=p)
    fmcos_conn = FMCOS(hw_conn=pm3_conn, fmcos_debug=DEBUG_FMCOS)

    internal_key = b"\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34"
    purchase_key = b"\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01"
    credit_key = b"\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01"
    pin_code = b"\x12\x34\x5F\xFF\xFF\xFF\xFF\xFF"
    terminal_id = b"\x66\x66\x66\x66\x66\x66"

    #print(args)
    match args.command:
        case 'select':
            if not waitForCard():
                raise ValueError("Unable to find card...")

            ret = fmcos_conn.cmd_select(args.id)
            assert_success(fmcos_conn, ret)

        case 'setup':
            if not waitForCard():
                raise ValueError("Unable to find card...")

            #Reset the card
            ret = fmcos_conn.cmd_select('3f00')
            assert_success(fmcos_conn, ret)

            ret = fmcos_conn.cmd_erase_df()
            assert_success(fmcos_conn, ret)

            #Create directory
            ret = fmcos_conn.cmd_create_directory(file_id=0x3f01, file_space=0x1500, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"walletTest")
            assert_success(fmcos_conn, ret)

            #Switch to directory
            ret = fmcos_conn.cmd_select(name=b"walletTest")
            assert_success(fmcos_conn, ret)

            #Create Keyfile
            ret = fmcos_conn.cmd_create_keyfile(file_id=0x0000, file_space=0x200, df_sid=0x95, key_permission=0xf0)
            assert_success(fmcos_conn, ret)

            #Create an InternalKey
            ret = fmcos_conn.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                change_rights=0x02, key_version=0x00, algo_id=0x01, key=internal_key)
            assert_success(fmcos_conn, ret)

            #Create PurchaseKey
            ret = fmcos_conn.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                change_rights=0x02, key_version=0x00, algo_id=0x01, key=purchase_key)
            assert_success(fmcos_conn, ret)

            #Create CreditKey
            ret = fmcos_conn.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                change_rights=0x02, key_version=0x00, algo_id=0x01, key=credit_key)
            assert_success(fmcos_conn, ret)

            #Create PinKey
            ret = fmcos_conn.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                followup_status=0x01, error_counter=0x33, key=pin_code)
            assert_success(fmcos_conn, ret)

            #Create a LoopFile for transaction tracking
            ret = fmcos_conn.cmd_create_file(file_id=0x0018, file_type=CPUFileType.LoopFile, file_size=0x0517, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
            assert_success(fmcos_conn, ret)

            #Create a LoopFile for transaction tracking
            ret = fmcos_conn.cmd_create_file(file_id=0x0019, file_type=CPUFileType.LoopFile, file_size=0x0517, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
            assert_success(fmcos_conn, ret)

            #Create a wallet and link it to the loopfile
            ret = fmcos_conn.cmd_create_edep(balance_type=BalanceType.Wallet, usage_rights=0xf0, loop_file_id=0x18)
            assert_success(fmcos_conn, ret)

            #Create a passbook and link it to the loopfile
            ret = fmcos_conn.cmd_create_edep(balance_type=BalanceType.Passbook, usage_rights=0xf0, loop_file_id=0x19)
            assert_success(fmcos_conn, ret)

        case 'reset':
            if not waitForCard():
                raise ValueError("Unable to find card...")

            ret = fmcos_conn.cmd_select('3f00')
            assert_success(fmcos_conn, ret)

            ret = fmcos_conn.cmd_erase_df()
            assert_success(fmcos_conn, ret)

        case 'verify_pin':
            if not waitForCard():
                raise ValueError("Unable to find card...")

            select_wallet()
            ret = fmcos_conn.cmd_verify_pin(key_id=0, pin_code=pin_code)
            assert_success(fmcos_conn, ret)

        case 'add_money':
            if not waitForCard():
                raise ValueError("Unable to find card...")
            select_wallet()
            
            ret = fmcos_conn.cmd_verify_pin(key_id=0, pin_code=pin_code)
            assert_success(fmcos_conn, ret)

            print(f"[{color('+', fg='green')}] Add Money => Wallet")
            ret = fmcos_conn.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=1, amount=100, terminal_id=terminal_id, \
                                    credit_key=credit_key, internal_key=internal_key)
            assert_success(fmcos_conn, ret)

            print(f"[{color('+', fg='green')}] Add Money => Passbook")
            ret = fmcos_conn.cmd_add_credit(balance_type=BalanceType.Passbook, key_id=1, amount=200, terminal_id=terminal_id, \
                                    credit_key=credit_key, internal_key=internal_key)
            assert_success(fmcos_conn, ret)

        case 'spend_money':
            if not waitForCard():
                raise ValueError("Unable to find card...")
            select_wallet()

            print(f"[{color('+', fg='green')}] Verifying PIN...")
            ret = fmcos_conn.cmd_verify_pin(key_id=0, pin_code=pin_code)
            assert_success(fmcos_conn, ret)

            print(f"[{color('+', fg='green')}] Use Money => Wallet")
            ret = fmcos_conn.cmd_purchase_wallet(key_id=1, amount=50, terminal_id=terminal_id, purchase_key=purchase_key, internal_key=internal_key)
            assert_success(fmcos_conn, ret)

            print(f"[{color('+', fg='green')}] Use Money => Passbook")
            ret = fmcos_conn.cmd_purchase_passbook(key_id=1, amount=50, terminal_id=terminal_id, purchase_key=purchase_key, internal_key=internal_key)
            assert_success(fmcos_conn, ret)

        case 'get_balance':
            if not waitForCard():
                raise ValueError("Unable to find card...")

            select_wallet()

            ret = fmcos_conn.cmd_get_balance(BalanceType.Wallet)
            assert_success(fmcos_conn, ret)
            wallet_balance = struct.unpack(">I", ret[:4])[0]
            print(f"[{color('+', fg='green')}] Wallet Balance: {wallet_balance}")

            ret = fmcos_conn.cmd_get_balance(BalanceType.Passbook)
            assert_success(fmcos_conn, ret)
            passbook_balance = struct.unpack(">I", ret[:4])[0]
            print(f"[{color('+', fg='green')}] Passbook Balance: {passbook_balance}")

if __name__ == "__main__":
    main()
