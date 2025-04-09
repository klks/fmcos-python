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
DEBUG_PN532 = True
DEBUG_ACR1518 = True

#References
#https://github.com/Tvirus/rfid_reader/blob/main/src/iso7816.c
#https://github.com/gao19970120/fmcosByPn532

if __name__ == '__main__':
    #pn532_conn = BRIDGE_PN532(com_port="COM11", hw_debug=DEBUG_PN532)
    hw_conn = BRIDGE_PYSCARD(reader_string="ACS ACR1581 1S Dual Reader PICC 0", hw_debug=DEBUG_ACR1518)
    exam = FMCOS(hw_conn=hw_conn, fmcos_debug=DEBUG_FMCOS)
    while (1):
        inp = input("> ")

        if len(inp) == 0:
            continue

        if inp.find("pn532_") != -1:
            pn_cmd = inp.split(" ")[0]

            while (exam.nfcFindCard() == 'noCard'):
                    print('noCard')

            match pn_cmd:
                case "pn532_GetFirmwareVersion":
                    exam.hw_conn.sendToNfc(b"\xD4\x02", custom_data=True)
                    ret = exam.hw_conn.nfcGetRawRecData()
                    print(bytes_to_hexstr(ret))
                case "pn532_uid":
                    while (uid := exam.nfcFindCard() ):
                        if uid == 'noCard':
                            print('noCard')
                        else:
                            print(f"[PN532_UID] {bytes_to_hexstr(uid)}")
                            break

        elif inp == "exit":
            break

        elif inp.find("fmcos_raw") != -1:
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            ret = exam.hw_conn.sendRaw(inp[10:])
            parse_return_code(ret[-2:])

        elif inp == "get4":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            exam.cmd_get_challenge()

        elif inp == "get8":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            exam.cmd_get_challenge(8)

        elif inp.find('select') != -1:
            try:
                while (exam.nfcFindCard() == 'noCard'):
                    print('noCard')

                selections = inp.split(" ")[1:]

                for sel in selections:
                    exam.cmd_select(sel)
            except:
                print(traceback.format_exc())

        elif inp == "external_auth":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            if not exam.is_success(exam.cmd_external_authenticate(key_id=0)):
                print("Failed to auth to card with default key")
            else:
                print("Authentication successful")

        elif inp == "reset":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                exam.cmd_select('3f00')

                ret = exam.cmd_erase_df()
                if not exam.is_success(ret):
                    ret = exam.cmd_external_authenticate(key_id=1, key=b'\xff\xff\xff\xff\xff\xff\xff\xff')
                    if not exam.is_success(ret):
                        ret = exam.cmd_external_authenticate(key_id=0, key=b'\xff\xff\xff\xff\xff\xff\xff\xff')
                        if not exam.is_success(ret):
                            raise ValueError("Wipe Failed")

                    ret = exam.cmd_erase_df()
                    if not exam.is_success(ret):
                        print("Wipe Failed")
                    else:
                        print("Card wiped")
                else:
                    print("Card wiped")

            except:
                print(traceback.format_exc())

        
        elif inp == 'wipe17':
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            try:
                exam.cmd_external_authenticate(key_id=0, key=b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F')
            except:
                print(traceback.format_exc())

        elif inp == "size_test":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            try:

                #Select MF
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                if not exam.is_success( exam.cmd_external_authenticate(key_id=1, key=b'\xff\xff\xff\xff\xff\xff\xff\xff') ):
                    exam.cmd_external_authenticate(key_id=0, key=b'\xff\xff\xff\xff\xff\xff\xff\xff')

                #Reset card
                ret = exam.cmd_erase_df()
                assert_success(exam, ret)
                
                file_size = 1000
                file_count = 1
                while True:
                    ret = exam.cmd_create_file(file_id=file_count, file_type=CPUFileType.BinFile, file_size=file_size, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                    if not exam.is_success(ret):
                        print(f"[+] {file_count}K Card...OK\n")
                        break
                    file_count += 1

                #Reset card
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)
                ret = exam.cmd_erase_df()
                assert_success(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == 'example_1':
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            try:

                #Example from https://github.com/gao19970120/fmcosByPn532/blob/master/run.py
                #exam.simulation(enabled=True)

                #faka
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xe0, 0x00, 0x00, Data=b'\x3f\x00\xf0\x01\xf4\xff\xff')
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0xf0, df_sid=0x01, key_permission=0xf4)
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xd4, 0x01, 0x01, Data=b'\x39\xf0\xf4\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff')
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                     change_rights=0xf4, followup_status=0x0f, error_counter=0xff, key=b"\xff\xff\xff\xff\xff\xff\xff\xff")
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xd4, 0x01, 0x02, Data=b'\x39\xf0\xf4\x04\xff\xff\xff\xff\xff\xff\xff\xff\xff')
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf4, followup_status=0x04, error_counter=0xff, key=b"\xff\xff\xff\xff\xff\xff\xff\xff")
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xd4, 0x01, 0x03, Data=b'\x39\xf0\xf3\x03\xff\xff\xff\xff\xff\xff\xff\xff\xff')
                ret = exam.cmd_write_key(key_add_update = 0x01, key_id=0x03, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf4, followup_status=0x03, error_counter=0xff, key=b"\xff\xff\xff\xff\xff\xff\xff\xff")
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xE0, 0x3f, 0x01, Data=b'\x38\x0f\xff\xf4\xf4\x81\xff\xfftlulock')
                ret = exam.cmd_create_directory(file_id=0x3f01, file_space=0x0fff, create_permissions=0xf4, erase_permission=0xf4, app_id=0x81, df_name=b"tlulock")
                assert_success(exam, ret)

                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xe0, 0x00, 0x00, Data=b'\x3f\x00\xf0\x81\xf4\xff\xff')
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0xf0, df_sid=0x81, key_permission=0xf4)
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xd4, 0x01, 0x01, Data=b'\x30\xf0\xf4\x05\x98\xff\xff\xff\xff\xff\xff\xff\xff')
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.DESEncrypt, usage_rights=0xf0, \
                                    change_rights=0xf4, key_version=0x05, algo_id=0x98, key=b"\xff\xff\xff\xff\xff\xff\xff\xff")
                assert_success(exam, ret)

                #exam.sendCommand(0x80, 0xE0, 0x00, 0x01, Data=b'\x28\x00\x0D\xf0\xf4\xff\xf1')
                ret = exam.cmd_create_file(file_id=0x0001, file_type=CPUFileType.BinFile, file_size=0x000d, read_perm=0xf0, write_perm=0xf4, access_rights=0xf1)
                assert_success(exam, ret)

                ret = exam.cmd_select('0001')
                assert_success(exam, ret)

                #exam.sendCommand(0x00, 0xd6, 0x00, 0x00, Data=b'appForTlulock')
                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"appForTlulock")
                assert_success(exam, ret)

                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x0D)
                assert_success(exam, ret)

                #duka
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                ret = exam.cmd_external_authenticate(key_id=3, key=b'\xff\xff\xff\xff\xff\xff\xff\xff')
                assert_success(exam, ret)

                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                ram = os.urandom(8)
                DESED = exam.cmd_internal_authenticate(p1=0, p2=1, data=ram)[:-2]   #Remove SW1_SW2

                print(f"DESED => {bytes_to_hexstr(DESED)}")
                key = b'\xff\xff\xff\xff\xff\xff\xff\xff'
                DESECB = DES.new(key, DES.MODE_ECB)
                if DESED==DESECB.encrypt(ram):
                    print('INTERNAL AUTHENTICATE success\n')
                else:
                    print('INTERNAL AUTHENTICATE failed\n')

                #exam.simulation(enabled=False)
                print("Example 1 execution complete")

            except:
                print(traceback.format_exc())

        elif inp == "example_2":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                #Example from https://blog.csdn.net/robur/article/details/137655286
                #exam.simulation(enabled=True)

                #Keys
                external_auth_key = b"\x11\x22\x33\x44\x55\x66\x77\x88"
                purchase_key = b"\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x11\x22\x33\x44\x55\x66\x77\x88"
                credit_key = b"\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x11\x22\x33\x44\x55\x66\x77\x88"
                internal_key = b"\x34\x34\x34\x34\x34\x34\x34\x34\x11\x22\x33\x44\x55\x66\x77\x88"
                pin_code = b"\x12\x34"
                terminal_id = b"\x66\x66\x66\x66\x66\x66"

                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                #Create Application 3f01
                #80 E0 3F 01 0D 38 08 00 F0 F0 95 FF FF 11 22 33 44 55
                ret = exam.cmd_create_directory(file_id=0x3f01, file_space=0x0800, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"\x11\x22\x33\x44")
                assert_success(exam, ret)

                #Select 3f01
                #00 A4 00 00 02 3F 01 00
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #Create Key file
                #80 E0 00 00 07 3F 01 8F 95 F0 FF FF
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0x18f, df_sid=0x95, key_permission=0xf0)
                assert_success(exam, ret)

                #Add External Authentication Key
                #80 D4 01 00 0D 39 F0 F0 AA FF 11 22 33 44 55 66 77 88
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=external_auth_key)
                assert_success(exam, ret)

                #Add Consumption Key
                #80 D4 01 00 15 3E F0 F0 00 01 3E 3E 3E 3E 3E 3E 3E 3E 11 22 33 44 55 66 77 88
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=purchase_key)
                assert_success(exam, ret)

                #Add Captive Key
                #80 D4 01 00 15 3F F0 F0 00 01 3F 3F 3F 3F 3F 3F 3F 3F 11 22 33 44 55 66 77 88
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=credit_key)
                assert_success(exam, ret)

                #Add DTK\TAC Key
                #80 D4 01 00 15 34 F0 F0 00 01 34 34 34 34 34 34 34 34 11 22 33 44 55 66 77 88
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=internal_key)
                assert_success(exam, ret)

                #Add Password/Pin Key - 1234
                #80 D4 01 00 07 3A F0 EF AA FF 12 34
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                    followup_status=0xaa, error_counter=0xff, key=pin_code)
                assert_success(exam, ret)

                #Create transaction record file 0018
                #80 E0 00 18 07 2E 0A 17 F0 EF FF FF
                ret = exam.cmd_create_file(file_id=0x0018, file_type=CPUFileType.LoopFile, file_size=0x0a17, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
                assert_success(exam, ret)

                #Create wallet file 0002
                #80 E0 00 02 07 2F 02 08 F0 00 FF 18
                ret = exam.cmd_create_edep(balance_type=BalanceType.Wallet, usage_rights=0xf0, loop_file_id=0x18)
                assert_success(exam, ret)


                #Read wallet balance
                #80 5C 00 02 04
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)

                #Verify Password/PIN - 1234
                #00 20 00 00 02 12 34
                ret = exam.cmd_verify_pin(key_id=0, pin_code=b"\x12\x34")
                assert_success(exam, ret)

                #Trap inititialization
                #80 50 00 02 0B [00] [00 00 00 10] [66 66 66 66 66 66] 10
                #This uses the KeyType.CreditKey and KeyType.InternalKey
                ret = exam.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=0, amount=0x10, terminal_id=terminal_id, \
                                            credit_key=credit_key, internal_key=internal_key)
                assert_success(exam, ret)

                #Read wallet balance
                #80 5C 00 02 04
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)

                #Read transaction history
                #00 B2 01 C4 00
                ret = exam.cmd_read_record(record_number=1, file_id=0x18)
                assert_success(exam, ret)

                #exam.simulation(enabled=False)
                print("Example 2 execution complete")

            except:
                print(traceback.format_exc())

        elif inp == "example_3":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            try:
                #Example from https://blog.csdn.net/lupengfei1009/article/details/53002341

                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                #800E 000000
                ret = exam.cmd_erase_df()
                assert_success(exam, ret)

                #80E0 3F00 0D 38 FFFF F0 F0 01 FFFF FFFFFFFFFF  #Modified to use 3f01 instead
                ret = exam.cmd_create_directory(file_id=0x3f01, file_space=0x1900, create_permissions=0xf0, erase_permission=0xf0, app_id=0x01, df_name=b"\xff\xff\xff\xff\xff")
                assert_success(exam, ret)

                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #80E0 0000 07 3F 0050 01 F0 FFFF
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0x50, df_sid=0x01, key_permission=0xf0)
                assert_success(exam, ret)

                #80D4 01 00 0D 36 F0 F0 FF 33 FFFFFFFFFFFFFFFF
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0xf0, error_counter=0x33, key=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
                assert_success(exam, ret) 

                #80D4 01 00 15 39 F0 F0 AA 33 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0x33, key=b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF")
                assert_success(exam, ret)

                #80E0 0001 07 2A 0213 F0 00 FF FF
                ret = exam.cmd_create_file(file_id=0x0001, file_type=CPUFileType.FixLength, file_size=0x0213, read_perm=0xf0, write_perm=0x00, access_rights=0xff)
                assert_success(exam, ret)

                #80E0 0005 07 A8 0030 F0 F0 FF FF
                ret = exam.cmd_create_file(file_id=0x0005, file_type=CPUFileType.BinFile, file_size=0x0030, read_perm=0xf0, write_perm=0xf0, access_rights=0xff, protection=Protection.LineProtect)
                assert_success(exam, ret)

                #00E2 00 08 13 61114F09A00000000386980701500450424F43
                ret= exam.cmd_append_record(file_id=0x0001, data=b"\x61\x11\x4F\x09\xA0\x00\x00\x00\x03\x86\x98\x07\x01\x50\x04\x50\x42\x4F\x43")

                #80E0 3F01 11 38 036F F0 F0 95 FFFF A00000000386980701
                ret = exam.cmd_create_directory(file_id=0x3f02, file_space=0x1100, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"\xA0\x00\x00\x00\x03\x86\x98\x07\x01")
                assert_success(exam, ret)

                #00A4 04 00 09 A00000000386980701
                ret = exam.cmd_select(name=b"\xA0\x00\x00\x00\x03\x86\x98\x07\x01")
                assert_success(exam, ret)

                #80E0 0000 07 3F 018F 95 F0 FFFF
                ret = exam.cmd_create_keyfile(file_id=0x0000, file_space=0x18f, df_sid=0x95, key_permission=0xf0)
                assert_success(exam, ret)

                #80D4 01 00 15 34 F0 02 00 01 34343434343434343434343434343434
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34")
                assert_success(exam, ret)

                #80D4 01 00 15 36 F0 02 FF 33 36363636363636363636363636363636
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=b"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36")
                assert_success(exam, ret)

                #80D4 01 00 15 37 F0 02 FF 33 37373737373737373737373737373737
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.UnlockPinKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=b"\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37")
                assert_success(exam, ret)

                #80D4 01 00 15 38 F0 02 FF 33 38383838383838383838383838383838
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ChangePinKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=b"\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38")
                assert_success(exam, ret)

                #80D4 01 00 15 39 F0 02 44 33 39393939393939393939393939393939
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0x02, followup_status=0x44, error_counter=0x33, key=b"\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39")
                assert_success(exam, ret)

                #80D4 01 01 15 3E F0 02 00 01 3E013E013E013E013E013E013E013E01
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01")
                assert_success(exam, ret)

                #80D4 01 02 15 3E F0 02 00 01 3E023E023E023E023E023E023E023E02
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.PurchaseKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02")
                assert_success(exam, ret)

                #80D4 01 01 15 3F F0 02 00 01 3F013F013F013F013F013F013F013F01
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01")
                assert_success(exam, ret)

                #80D4 01 02 15 3F F0 02 00 01 3F023F023F023F023F023F023F023F02
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.CreditKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02")
                assert_success(exam, ret)

                #80D4 01 01 15 3D F0 02 01 00 3D013D013D013D013D013D013D013D01
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.DebitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3D\x01\x3D\x01\x3D\x01\x3D\x01\x3D\x01\x3D\x01\x3D\x01\x3D\x01")
                assert_success(exam, ret)

                #80D4 01 02 15 3D F0 02 01 00 3D023D023D023D023D023D023D023D02
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.DebitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3D\x02\x3D\x02\x3D\x02\x3D\x02\x3D\x02\x3D\x02\x3D\x02\x3D\x02")
                assert_success(exam, ret)

                #80D4 01 01 15 3C F0 02 01 00 3C013C013C013C013C013C013C013C01
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x01, key_type=KeyType.OverdrawLimitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3C\x01\x3C\x01\x3C\x01\x3C\x01\x3C\x01\x3C\x01\x3C\x01\x3C\x01")
                assert_success(exam, ret)

                #80D4 01 02 15 3C F0 02 01 00 3C023C023C023C023C023C023C023C02
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.OverdrawLimitKey, usage_rights=0xf0, \
                                    change_rights=0x02, key_version=0x00, algo_id=0x01, key=b"\x3C\x02\x3C\x02\x3C\x02\x3C\x02\x3C\x02\x3C\x02\x3C\x02\x3C\x02")
                assert_success(exam, ret)

                #80D4 01 00 0D 3A F0 EF 01 33 12345FFFFFFFFFFF
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.PinKey, usage_rights=0xf0, \
                                    followup_status=0x01, error_counter=0x33, key=b"\x12\x34\x5F\xFF\xFF\xFF\xFF\xFF")
                assert_success(exam, ret)

                #80E0 0015 07 A8 001E F0 F0 FF FF
                ret = exam.cmd_create_file(file_id=0x0015, file_type=CPUFileType.BinFile, file_size=0x001e, read_perm=0xf0, write_perm=0xf0, access_rights=0xff, protection=Protection.LineProtect)
                assert_success(exam, ret)

                #80E0 0016 07 A8 0027 F0 F0 FF FF
                ret = exam.cmd_create_file(file_id=0x0016, file_type=CPUFileType.BinFile, file_size=0x0027, read_perm=0xf0, write_perm=0xf0, access_rights=0xff, protection=Protection.LineProtect)
                assert_success(exam, ret)

                #80E0 0017 07 28 05DC F0 F0 FF FF
                ret = exam.cmd_create_file(file_id=0x0017, file_type=CPUFileType.BinFile, file_size=0x05DC, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)

                #80E0 0018 07 2E 0A17 F0 EF FF FF
                ret = exam.cmd_create_file(file_id=0x0018, file_type=CPUFileType.LoopFile, file_size=0x0a17, read_perm=0xf0, write_perm=0xef, access_rights=0xff)
                assert_success(exam, ret)

                #80E0 0001 07 2F 0208 F1 00 FF 18
                ret = exam.cmd_create_edep(balance_type=BalanceType.Passbook, usage_rights=0xf0, loop_file_id=0x18)
                assert_success(exam, ret)

                #80E0 0002 07 2F 0208 F0 00 FF 18
                ret = exam.cmd_create_edep(balance_type=BalanceType.Wallet, usage_rights=0xf0, loop_file_id=0x18)
                assert_success(exam, ret)

                print("Example 3 execution complete")
            except:
                print(traceback.format_exc())

        elif inp == "example_3a":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')
            try:
                terminal_id = b"\x66\x66\x66\x66\x66\x66"
                credit_key_1 = b"\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01\x3F\x01"
                credit_key_2 = b"\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02\x3F\x02"
                purchase_key_1 = b"\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01\x3E\x01"
                purchase_key_2 = b"\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02\x3E\x02"
                internal_key = b"\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34"

                #Select directory
                ret = exam.cmd_select(name=b"\xA0\x00\x00\x00\x03\x86\x98\x07\x01")
                assert_success(exam, ret)

                #Perform pin auth
                ret = exam.cmd_verify_pin(key_id=0, pin_code=b"\x12\x34\x5F\xFF\xFF\xFF\xFF\xFF")
                assert_success(exam, ret)

                #Check balance
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)
                
                #Add credit to wallet 1 using credit_key #1
                ret = exam.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=1, amount=0x1000, terminal_id=terminal_id, \
                                            credit_key=credit_key_1, internal_key=internal_key)
                assert_success(exam, ret)

                #Check balance
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)

                #Add credit to wallet 2 using credit_key #2
                ret = exam.cmd_add_credit(balance_type=BalanceType.Wallet, key_id=2, amount=0x1000, terminal_id=terminal_id, \
                                            credit_key=credit_key_2, internal_key=internal_key)
                assert_success(exam, ret)

                #Check balance
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)

                #Spend some money
                ret = exam.cmd_purchase_wallet(key_id=1, amount=0x500, terminal_id=terminal_id, purchase_key=purchase_key_1, internal_key=internal_key)
                assert_success(exam, ret)

                #Check balance
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)

                ret = exam.cmd_purchase_wallet(bkey_id=2, amount=0x500, terminal_id=terminal_id, purchase_key=purchase_key_2, internal_key=internal_key)
                assert_success(exam, ret)

                #Check balance
                ret = exam.cmd_get_balance(balance_type=BalanceType.Wallet)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        else:
            print(f"Unknown command : {inp}")