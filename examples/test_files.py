"""Comprehensive file/record/loop protection demo for FMCOS.

Shows creation of various file types (binary, variable, loop) with optional
line protection (MAC only or MAC+encryption), plus block/unblock flows.
Interactive: run and type commands like setup, write_binary, read_record, etc.
"""
import sys
import os
import traceback
from Crypto.Cipher import DES  # type: ignore
from conn_pn532 import BRIDGE_PN532
from conn_pyscard import BRIDGE_PYSCARD
from fmcos import CPUFileType, KeyType, BalanceType, Protection, ApplicationBlock
from fmcos import parse_return_code, FMCOS
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

if __name__ == '__main__':
    #Keys used
    internal_key = b"\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34\x34"
    line_protection_key = b"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36"
    external_auth_key = b"\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39\x39"

    line_protection_key_1 = b"\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37\x37"
    external_auth_key_1 = b"\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A"
    internal_key_1 = b"\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B"

    enc_external_auth_key = b"\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38\x38"

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

                ret = exam.cmd_erase_df()
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "setup":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                #===============================================================================================================
                #Create an ADF
                ret = exam.cmd_create_directory(file_id=0x3fff, file_space=0x500, create_permissions=0xf0, erase_permission=0xf0, app_id=0x94, df_name=b"blockTest")
                assert_success(exam, ret)

                #Switch to directory
                ret = exam.cmd_select(name=b"blockTest")
                assert_success(exam, ret)

                #Create Keyfile
                ret = exam.cmd_create_keyfile(file_id=0x0001, file_space=0x200, df_sid=0x94, key_permission=0xf0)
                assert_success(exam, ret)

                #Create FileLineProtectionKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0x02, error_counter=0x33, key=line_protection_key_1)
                assert_success(exam, ret)

                #create ExternalAuthenticationKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=external_auth_key_1)
                assert_success(exam, ret)

                #Create an InternalKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=internal_key_1)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x0002, file_type=CPUFileType.BinFile, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)

                ret = exam.cmd_select('0002')
                assert_success(exam, ret)

                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"binfile_block_test")
                assert_success(exam, ret)

                #===============================================================================================================
                #Back to parent 3F00
                ret = exam.cmd_select('3f00')
                assert_success(exam, ret)

                #Create an ADF
                ret = exam.cmd_create_directory(file_id=0x3f01, file_space=0x1500, create_permissions=0xf0, erase_permission=0xf0, app_id=0x95, df_name=b"fileTest")
                assert_success(exam, ret)

                #Switch to directory
                ret = exam.cmd_select(name=b"fileTest")
                assert_success(exam, ret)

                #Create Keyfile
                ret = exam.cmd_create_keyfile(file_id=0x0001, file_space=0x200, df_sid=0x95, key_permission=0xf0)
                assert_success(exam, ret)

                #create ExternalAuthenticationKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=external_auth_key)
                assert_success(exam, ret)

                #Create an InternalKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.InternalKey, usage_rights=0xf0, \
                                    change_rights=0xf0, key_version=0x00, algo_id=0x01, key=internal_key)
                assert_success(exam, ret)

                #Create FileLineProtectionKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x00, key_type=KeyType.FileLineProtectionKey, usage_rights=0xf0, \
                                    change_rights=0xf0, error_counter=0xff, key=line_protection_key, \
                                    extauth_key=external_auth_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)

                #create Encrypted + MAC ExternalAuthenticationKey
                ret = exam.cmd_write_key(key_add_update=0x01, key_id=0x02, key_type=KeyType.ExternalAuthenticationKey, usage_rights=0xf0, \
                                    change_rights=0xf0, followup_status=0xaa, error_counter=0xff, key=enc_external_auth_key, \
                                    extauth_key=external_auth_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)

                #Access rights table
                #|================================================================================|
                #| b08 | b07 | b06 | b05 | b04 | b03 | b02 | b01 |             Notes              |
                #|================================================================================|
                #|  1  |  -  |  -  |  -  |  -  |  -  |  -  |  -  |   MAC/Encryption Not Required  |
                #|  0  |  -  |  -  |  -  |  -  |  -  |  -  |  -  |     MAC/Encryption Required    |
                #|  -  |  1  |  1  |  1  |  -  |  -  |  -  |  -  |            Reserved            |
                #|=================================================================================
                #|  -  |  -  |  -  |  -  |  1  |  1  |  -  |  -  | =============== | Use Key ID 0 |
                #|  -  |  -  |  -  |  -  |  1  |  0  |  -  |  -  | |     Read    | | Use Key ID 1 |
                #|  -  |  -  |  -  |  -  |  0  |  1  |  -  |  -  | | Permissions | | Use Key ID 2 |
                #|  -  |  -  |  -  |  -  |  0  |  0  |  -  |  -  | =============== | Use Key ID 3 |
                #|=================================================================================
                #|  -  |  -  |  -  |  -  |  -  |  -  |  1  |  1  | ==============  | Use Key ID 0 |
                #|  -  |  -  |  -  |  -  |  -  |  -  |  1  |  0  | |    Write    | | Use Key ID 1 |
                #|  -  |  -  |  -  |  -  |  -  |  -  |  0  |  1  | | Permissions | | Use Key ID 2 |
                #|  -  |  -  |  -  |  -  |  -  |  -  |  0  |  0  | ==============  | Use Key ID 3 |
                #|=================================================================================

                #===============================================================================================================
                #Binfile
                ret = exam.cmd_create_file(file_id=0x0002, file_type=CPUFileType.BinFile, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x0003, file_type=CPUFileType.BinFile, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x0004, file_type=CPUFileType.BinFile, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)

                #===============================================================================================================
                #Variable Length Record File
                ret = exam.cmd_create_file(file_id=0x0006, file_type=CPUFileType.VariableLength, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x0007, file_type=CPUFileType.VariableLength, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x0008, file_type=CPUFileType.VariableLength, file_size=0x50, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)

                #===============================================================================================================
                #Write Loopfile
                #The first byte is the number of records, the second is the length of a record
                #Space calculation (record count * (record length + 1) + 8)
                #For 5 records with 0x50 bytes it is 0x550, total space used is (5 * (0x50+1) + 8) = 0x19D
                ret = exam.cmd_create_file(file_id=0x000a, file_type=CPUFileType.LoopFile, file_size=0x210, read_perm=0xf0, write_perm=0xf0, access_rights=0xff)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x000b, file_type=CPUFileType.LoopFile, file_size=0x210, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_create_file(file_id=0x000c, file_type=CPUFileType.LoopFile, file_size=0x210, read_perm=0xf0, write_perm=0xf0, access_rights=0x7f, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "write_binary":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #Binary
                ret = exam.cmd_select('0002')
                assert_success(exam, ret)
                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x10\x1a\x1b\x1c\x1d\x1e\x1f")
                assert_success(exam, ret)

                ret = exam.cmd_select('0003')
                assert_success(exam, ret)
                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x20\x2a\x2b\x2c\x2d\x2e\x2f", key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_select('0004')
                assert_success(exam, ret)
                ret = exam.cmd_update_binary(p1=0, p2=0, data=b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x3a\x3b\x3c\x3d\x3e\x3f", key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "write_loop":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #Binary
                ret = exam.cmd_select('000a')
                assert_success(exam, ret)
                ret = exam.cmd_append_record(file_id=0x0a, data=b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x90\x9a\x9b\x9c\x9d\x9e\x9f")
                assert_success(exam, ret)

                ret = exam.cmd_select('000b')
                assert_success(exam, ret)
                ret = exam.cmd_append_record(file_id=0x0b, data=b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xa0\xaa\xab\xac\xad\xae\xaf", key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_select('000c')
                assert_success(exam, ret)
                ret = exam.cmd_append_record(file_id=0x0c, data=b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xb0\xba\xbb\xbc\xbd\xbe\xbf", key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "write_record":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                #Record
                #P1 is the record number, 0 means current record
                #P2 is the file_id
                #|======================================================================================|
                #| b08 | b07 | b06 | b05 | b04 | b03 | b02 | b01 |                 Notes                |
                #|======================================================================================|
                #|  X  |  X  |  X  |  X  |  X  |  -  |  -  |  -  |   File Identifier (Non-Zero Values)  |
                #|  0  |  0  |  0  |  0  |  0  |  -  |  -  |  -  |   Use Current File                   |
                #|  0  |  -  |  -  |  -  |  -  |  1  |  0  |  0  |   Use value in P1                    |
                #|  0  |  -  |  -  |  -  |  -  |  0  |  0  |  0  |   P1 points to first record marked   |
                #|  0  |  -  |  -  |  -  |  -  |  0  |  0  |  1  |   P1 points to last record marked    |
                #|  0  |  -  |  -  |  -  |  -  |  0  |  1  |  0  |   P1 points to next record marked    |
                #|  0  |  -  |  -  |  -  |  -  |  0  |  1  |  1  |   P1 points to prev record marked    |
                #|======================================================================================|
                ret = exam.cmd_select('0006')
                assert_success(exam, ret)
                ret = exam.cmd_update_record(record_number=1, file_id=0x06, data=b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x50\x5a\x5b\x5c\x5d\x5e\x5f", use_tlv=True)
                assert_success(exam, ret)

                ret = exam.cmd_select('0007')
                assert_success(exam, ret)
                ret = exam.cmd_update_record(record_number=1, file_id=0x07, data=b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x60\x6a\x6b\x6c\x6d\x6e\x6f", use_tlv=True, key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)

                ret = exam.cmd_select('0008')
                assert_success(exam, ret)
                ret = exam.cmd_update_record(record_number=1, file_id=0x08, data=b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x70\x7a\x7b\x7c\x7d\x7e\x7f", use_tlv=True, key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "read_binary":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                ret = exam.cmd_select('0002')
                assert_success(exam, ret)
                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x10)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-2])}\n")

                ret = exam.cmd_select('0003')
                assert_success(exam, ret)
                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x10, key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-6])} MAC => {bytes_to_hexstr(ret[-6:-2])}\n")

                ret = exam.cmd_select('0004')
                assert_success(exam, ret)
                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x10, key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-2])}\n")
            except:
                print(traceback.format_exc())

        elif inp == "read_record":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x06, read_length=0x10, has_tlv=True)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-2])}\n")

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x07, read_length=0x10, has_tlv=True, key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-6])} MAC => {bytes_to_hexstr(ret[-6:-2])}\n")

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x08, read_length=0x10, has_tlv=True, key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "read_loop":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select('3f01')
                assert_success(exam, ret)

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x0a)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-2])}\n")

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x0b, key=line_protection_key, protection=Protection.LineProtect)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-6])} MAC => {bytes_to_hexstr(ret[-6:-2])}\n")

                ret = exam.cmd_read_record(record_number=0x01, file_id=0x0c, key=line_protection_key, protection=Protection.LineProtectEncrypt)
                assert_success(exam, ret)
            except:
                print(traceback.format_exc())

        elif inp == "card_block":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"blockTest")
                assert_success(exam, ret)

                ret = exam.cmd_app_block(block_type=ApplicationBlock.Permenant, line_key=line_protection_key_1)
                assert_success(exam, ret)

                ret = exam.cmd_select('0002')
                assert_failure(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == "app_block":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"blockTest")
                assert_success(exam, ret)

                ret = exam.cmd_app_block(block_type=ApplicationBlock.Temporary, line_key=line_protection_key_1)
                assert_success(exam, ret)

                ret = exam.cmd_select('0002')
                assert_failure(exam, ret)

            except:
                print(traceback.format_exc())

        elif inp == "app_unblock":
            while (exam.nfcFindCard() == 'noCard'):
                print('noCard')

            try:
                ret = exam.cmd_select(name=b"blockTest")
                assert_failure(exam, ret)

                ret = exam.cmd_app_unblock(line_key=line_protection_key_1)
                assert_success(exam, ret)

                ret = exam.cmd_select('0002')
                assert_success(exam, ret)

                ret = exam.cmd_read_binary(p1=0, p2=0, read_length=0x10)
                assert_success(exam, ret)
                print(f"Data: {bytes_to_hexstr(ret[:-2])}\n")

            except:
                print(traceback.format_exc())