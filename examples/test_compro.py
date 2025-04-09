import sys
import os
import traceback
from Crypto.Cipher import DES
from conn_pn532 import BRIDGE_PN532
from conn_pyscard import BRIDGE_PYSCARD
from fmcos import CPUFileType, KeyType, BalanceType, Protection, parse_return_code, FMCOS
from utils import bytes_to_hexstr, assert_success

# optional color support .. `pip install ansicolors`
try:
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

DEBUG_FMCOS = True
DEBUG_PN532 = False

if __name__ == '__main__':
    #Keys used
    external_auth_key = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    line_protection_key = b"\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f"
    pin_code = b"\x12\x34\x56"

    external_auth_key_1 = b"\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f"
    internal_key_1 = b"\x29\xc4\xc3\x30\xbd\xd8\xaf\x34\xd2\x31\x30\x82\xe5\x38\x03\xff"
    line_protection_key_2 = b"\x07\x45\x2a\x90\x55\x6d\x72\x2d\x40\x5f\x65\xc8\x96\xd7\x79\x1f"
    purchase_key_1 = b"\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f"
    credit_key_1 = b"\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f\x1f"
    terminal_id = b"000000"

    hw_conn = BRIDGE_PN532(com_port="COM11", hw_debug=DEBUG_PN532)    
    exam = FMCOS(hw_conn=hw_conn, fmcos_debug=DEBUG_FMCOS)
    while (1):
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

                ret = exam.cmd_external_authenticate(key_id=0, key=external_auth_key)
                assert_success(exam, ret)

                ret = exam.cmd_erase_df()
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "setup":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                #exam.simulation(enabled=True)

                #Example from FM1208_Test_compro-v2.html
                #> 00a4 00 00 02 3f00 
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                #> 80e0 0001 07 3f 0040 00 f0 ffff
                ret = exam.cmd_create_keyfile(file_id=0x0001, file_space=0x40, df_sid=0x0, key_permission=0xf0)
                assert_success(exam, ret)
                
                #> 80d4 01 00 15 f9 f0 f0 aa ff ffffffffffffffffffffffffffffffff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=external_auth_key)
                assert_success(exam, ret)

                
                #> 80d4 01 00 15 f6 f0 f0 ff ff ffffffffffffffffffffffffffffffff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0xf0, error_counter=0xff, key=line_protection_key, \
                                    extauth_key=external_auth_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                
                #> 80d4 01 00 08 3a f0 ef 01 ff 123456
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                    followup_status=0x01, error_counter=0xff, key=pin_code)
                assert_success(exam, ret)
                
                #> 80e0 0002 07 a8 0200 f0 f1 ff 7f
                ret = exam.cmd_create_file(file_id=0x0002, file_type=CPUFileType.BinFile, file_size=0x0200, read_perm=0xf0, write_perm=0xf1, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)
                
                #> 80e0 0003 07 2a 0208 f0 f0 ff ff
                ret = exam.cmd_create_file(file_id=0x0003, file_type=CPUFileType.FixLength, file_size=0x0208, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)
                
                #> 80e0 0004 07 2e 0208 f0 f0 ff ff
                ret = exam.cmd_create_file(file_id=0x0004, file_type=CPUFileType.LoopFile, file_size=0x0208, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)
                
                #> 80e0 0005 07 2c 0208 f0 f0 ff ff
                ret = exam.cmd_create_file(file_id=0x0005, file_type=CPUFileType.VariableLength, file_size=0x0208, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)
                
                #> 0020 00 00 03 123456
                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)
                
                #> 00a40000020002
                ret = exam.cmd_select('0002')
                assert_success(exam, ret)
                
                #> 04d6 00 00 14 11223344556677889900aabbccddeeff f2f62231
                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\xaa\xbb\xcc\xdd\xee\xff", key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)
                
                #> 04b0 00 00 04 f09c8a19 10
                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x10, key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)
                print(f"Data => {bytes_to_hexstr(ret[:-6])}\n")
                
                #> 00dc 01 1c 08 1122334455667788
                ret = exam.cmd_update_record(record_number=0x01, file_id=0x03, data=b"\x11\x22\x33\x44\x55\x66\x77\x88")
                assert_success(exam, ret)
                
                #> 00b2 01 1c 08
                ret = exam.cmd_read_record(record_number=0x01, file_id=0x03)
                assert_success(exam, ret)
                
                #> 00e2 00 24 08 1122334455667788
                ret = exam.cmd_append_record(file_id=0x04, data=b"\x11\x22\x33\x44\x55\x66\x77\x88")
                assert_success(exam, ret)
                
                #> 00b2 01 24 08
                ret = exam.cmd_read_record(record_number=1, file_id=0x04)
                assert_success(exam, ret)
                
                #> 00dc 01 2c 08 bb06112233445566
                ret = exam.cmd_update_record(record_number=0x01, file_id=0x05, data=b"\xbb\x06\x11\x22\x33\x44\x55\x66")
                assert_success(exam, ret)
                
                #> 80e0 df01 0f 38 01f1 f0 f0 95 7fff 54657374446972
                ret = exam.cmd_create_directory(file_id=0xdf01, file_space=0x01f1, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"TestDir")
                assert_success(exam, ret)
                
                #> 00a4000002df01
                ret = exam.cmd_select('df01')
                assert_success(exam, ret)
                
                #> 80e0 0000 07 3f 00b0 95 f0 ffff
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0xb0, df_sid=0x95, key_permission=0xf0)
                assert_success(exam, ret)
                
                #> 80e0 0015 07 a8 001e f0 f0 ff 7f
                ret = exam.cmd_create_file(file_id=0x0015, file_type=CPUFileType.BinFile, file_size=0x1e, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)
                
                #> 80e0 0016 07 a8 0037 f0 f0 ff 7f
                ret = exam.cmd_create_file(file_id=0x0016, file_type=CPUFileType.BinFile, file_size=0x37, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)
                
                #> 80e0 0002 07 2f 0208 f0 00 ff 18
                ret = exam.cmd_create_edep(balance_type=BalanceType.Wallet, usage_rights=0xf0, loop_file_id=0x18)
                assert_success(exam, ret)
                
                #> 80e0 0018 07 2e 0217 f1 ef ff ff
                ret = exam.cmd_create_file(file_id=0x0018, file_type=CPUFileType.LoopFile, file_size=0x0217, read_perm=0xf1, write_perm=0xef, access_rights=0xff)
                assert_success(exam, ret)
                
                #> 80e0 0017 07 ac 0040 f0 f0 ff ff
                ret = exam.cmd_create_file(file_id=0x0017, file_type=CPUFileType.VariableLength, file_size=0x40, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)
                
                #> 80d4 01 00 15 f9 f0 f0 aa ff ffffffffffffffffffffffffffffffff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=external_auth_key_1, \
                                    extauth_key=external_auth_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)

                #> 80d4 01 00 15 f4 f0 ef 03 00 29c4c330bdd8af34d2313082e53803ff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf4, \
                                    change_rights=0xf0, key_version=0x03, algo_id=0x00, key=internal_key_1,\
                                    extauth_key=external_auth_key_1, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                
                #> 80d4 01 00 15 f6 f0 ef ff ff 07452a90556d722d405f65c896d7791f
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0xf0, error_counter=0xff, key=line_protection_key_2, \
                                    extauth_key=external_auth_key_1, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                
                #> 80d4 01 00 08 3a f0 ef 01 ff 123456
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                    followup_status=0x01, error_counter=0xff, key=pin_code)
                assert_success(exam, ret)
                
                #> 80d4 01 00 15 fe f0 f0 01 00 ffffffffffffffffffffffffffffffff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x01, algo_id=0x00, key=purchase_key_1, \
                                    extauth_key=external_auth_key_1, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                
                #> 80d4 01 00 15 ff f0 f0 01 00 ffffffffffffffffffffffffffffffff
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=credit_key_1, \
                                    extauth_key=external_auth_key_1, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                
                #> 0020 00 00 03 123456
                ret = exam.cmd_verify_pin(key_id=0, pin_code=pin_code)
                assert_success(exam, ret)
                
                #> 8050 00 02 0b 00 000000c8 303030303030 10
                #> 8052 00 00 0b 20241220 150000 2e77bb82 04
                ret = exam.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=0, amount=200, terminal_id=terminal_id, \
                                        credit_key=credit_key_1, internal_key=internal_key_1)
                assert_success(exam, ret)
                
                #> 8050 01 02 0b 01 00000032 303030303030 0f
                #> 8054 01 00 0f 00001212 20241220 150518 be11d8d508
                ret = exam.cmd_purchase_wallet(key_id=0, amount=50, terminal_id=terminal_id, purchase_key=purchase_key_1, internal_key=internal_key_1)
                assert_success(exam, ret)

                #> 805c 00 02 04
                ret = exam.cmd_get_balance(BalanceType.Wallet)
                assert_success(exam, ret)
                
                #> 00a4 0000023f0000
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)
                                
                #> 0082 00 00 08 49093cabfab7c8ec
                ret = exam.cmd_external_authenticate(key_id=0, key=external_auth_key)
                assert_success(exam, ret)
                
                #> 800e000000
                ret = exam.cmd_erase_df()
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())

