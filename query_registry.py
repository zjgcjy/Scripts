from ctypes import *
from datetime import datetime, timezone, timedelta
from struct import pack, unpack

BYTE = c_byte
CHAR = c_char
WCHAR = c_wchar
LPCWSTR = LPWSTR = c_wchar_p
LPCSTR = LPSTR = c_char_p
WORD = c_ushort
DWORD = c_ulong
HKEY = HANDLE = c_void_p
LARGE_INTEGER = c_longlong
LPDWORD = PDWORD = POINTER(DWORD)
PHKEY = POINTER(HKEY)

#
MAX_KEYNAME_LEN = 260
MAX_VALUENAME_LEN = 260
MAX_VALUEDATA_LEN = 1024
# filetime
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as filetime
HUNDREDS_OF_NS = 10000000


class FILETIME(Structure):
    _fields_ = [("dwLowDateTime", DWORD),
                ("dwHighDateTime", DWORD)]


# reg value type
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11
REG_QWORD_LITTLE_ENDIAN = 11
# reg defined root
HKEY_CLASSES_ROOT = HKEY(0x80000000)
HKEY_CURRENT_USER = HKEY(0x80000001)
HKEY_LOCAL_MACHINE = HKEY(0x80000002)
HKEY_USERS = HKEY(0x80000003)
HKEY_PERFORMANCE_DATA = HKEY(0x80000004)
HKEY_PERFORMANCE_TEXT = HKEY(0x80000050)
HKEY_PERFORMANCE_NLSTEXT = HKEY(0x80000060)
# reg key right
KEY_QUERY_VALUE = DWORD(0x0001)
KEY_SET_VALUE = DWORD(0x0002)
KEY_CREATE_SUB_KEY = DWORD(0x0004)
KEY_ENUMERATE_SUB_KEYS = DWORD(0x0008)
KEY_NOTIFY = DWORD(0x0010)
KEY_CREATE_LINK = DWORD(0x0020)
KEY_WOW64_32KEY = DWORD(0x0200)
KEY_WOW64_64KEY = DWORD(0x0100)
KEY_WOW64_RES = DWORD(0x0300)
READ_CONTROL = DWORD(0x00020000)
SYNCHRONIZE = DWORD(0x00100000)
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
STANDARD_RIGHTS_ALL = DWORD(0x001F0000)
KEY_READ = DWORD(((STANDARD_RIGHTS_READ.value | \
                   KEY_QUERY_VALUE.value | \
                   KEY_ENUMERATE_SUB_KEYS.value | \
                   KEY_NOTIFY.value) \
                  & \
                  (~SYNCHRONIZE.value)))
KEY_WRITE = DWORD(((STANDARD_RIGHTS_WRITE.value | \
                    KEY_SET_VALUE.value | \
                    KEY_CREATE_SUB_KEY.value) \
                   & \
                   (~SYNCHRONIZE.value)))
KEY_EXECUTE = DWORD(((KEY_READ.value) \
                     & \
                     (~SYNCHRONIZE.value)))
KEY_ALL_ACCESS = DWORD(((STANDARD_RIGHTS_ALL.value | \
                         KEY_QUERY_VALUE.value | \
                         KEY_SET_VALUE.value | \
                         KEY_CREATE_SUB_KEY.value | \
                         KEY_ENUMERATE_SUB_KEYS.value | \
                         KEY_NOTIFY.value | \
                         KEY_CREATE_LINK.value) \
                        & \
                        (~SYNCHRONIZE.value)))


class reg():

    def __init__(self, root, key=u"", right=KEY_READ) -> None:
        self.root = root
        self.key = key
        self.right = right
        self.h_key = HKEY()
        self.subkey_num = DWORD()
        self.subkey_name_max = DWORD(MAX_KEYNAME_LEN)
        self.value_num = DWORD()
        self.value_name_max = DWORD(MAX_VALUENAME_LEN)
        self.value_data_max = DWORD(MAX_VALUEDATA_LEN)

        self.keytime = FILETIME()
        self.subkey_lasttime = FILETIME()
        try:
            self.reg_openkey = cdll.LoadLibrary("Advapi32.dll").RegOpenKeyExW
            self.reg_querykey = cdll.LoadLibrary("Advapi32.dll").RegQueryInfoKeyW
            self.reg_enumkey = cdll.LoadLibrary("Advapi32.dll").RegEnumKeyExW
            self.reg_enumvalue = cdll.LoadLibrary("Advapi32.dll").RegEnumValueW
            self.reg_queryvalue = cdll.LoadLibrary("Advapi32.dll").RegQueryValueExW
        except FileNotFoundError:
            print("File not found")
            exit(-1)
        except AttributeError:
            print("Function not found")
            exit(-1)

    def open_key(self):
        ret = self.reg_openkey(self.root, LPCWSTR(self.key), 0, self.right, byref(self.h_key))
        try:
            assert (ret == 0)
        except AssertionError as e:
            print(f'[OPEN_KEY] error: {ret}')
            exit(-1)
        print(f'[OPEN_KEY] handle: {self.h_key.value}')

    def query_key(self):
        ret = self.reg_querykey(self.h_key, 0, 0, 0,
                                byref(self.subkey_num),
                                byref(self.subkey_name_max), 0,
                                byref(self.value_num),
                                byref(self.value_name_max),
                                byref(self.value_data_max), 0,
                                byref(self.keytime))
        try:
            assert (ret == 0)
        except AssertionError as e:
            print(f'[QUERY_KEY] error: {ret}')
            exit(-1)
        print(f'[QUERY_KEY] subkey_num: {self.subkey_num.value}')
        print(f'[QUERY_KEY] subkey_name_max: {self.subkey_name_max.value}')
        print(f'[QUERY_KEY] value_num: {self.value_num.value}')
        print(f'[QUERY_KEY] value_name_max: {self.value_name_max.value}')
        print(f'[QUERY_KEY] value_data_max: {self.value_data_max.value}')
        time = self.filetime_to_datetime(self.keytime)
        print(f'[QUERY_KEY] {time}')

    def enum_key(self):
        keyname_type = c_wchar * (self.subkey_name_max.value + 1)
        keyname = keyname_type()
        subkey_time = FILETIME()
        for i in range(self.subkey_num.value):
            subkey_name_len = DWORD(self.subkey_name_max.value + 1)
            ret = self.reg_enumkey(self.h_key, DWORD(i),
                                   keyname,
                                   byref(subkey_name_len), 0, 0, 0,
                                   byref(subkey_time))
            try:
                assert (ret == 0)
            except AssertionError as e:
                print(f'[ENUM_KEY] error: {ret}')
                exit(-1)
            time = self.filetime_to_datetime(subkey_time)
            print(f'[ENUM_KEY] {keyname.value}: {time}')

    def enum_value(self):
        valuename_type = c_wchar * (self.value_name_max.value + 1)
        valuename = valuename_type()
        value_type = DWORD()
        data_type = BYTE * (self.value_data_max.value + 1)
        data = data_type()
        for i in range(self.value_num.value):
            valuename_len = DWORD(self.value_name_max.value + 1)
            data_len = DWORD(self.value_data_max.value + 1)
            ret = self.reg_enumvalue(self.h_key, DWORD(i),
                                     valuename,
                                     byref(valuename_len), 0,
                                     byref(value_type),
                                     data,
                                     byref(data_len))
            try:
                assert (ret == 0)
            except AssertionError as e:
                print(f'[ENUM_VALUE] error: {ret}')
                exit(-1)
            if value_type.value == REG_BINARY:
                print(f'[ENUM_VALUE] REG_BINARY: {valuename.value}')
            elif value_type.value == REG_DWORD:
                print(f'[ENUM_VALUE] REG_DWORD: {valuename.value}')
            else:
                assert (1 == 0)
            # print(f'[ENUM_VALUE] data_len: {data_len.value}')
            output = bytes(map(lambda x: x % 0x100, data[:data_len.value]))
            print(f'[ENUM_VALUE] data: {output}')

    def query_value(self, name):
        value_type = DWORD()
        value_len = DWORD()
        ret = self.reg_queryvalue(self.h_key, LPCWSTR(name), 0, byref(value_type), 0, byref(value_len))
        try:
            assert (ret == 0)
        except AssertionError as e:
            if ret == 2:
                print(f'[QUERY_VALUE] error: {name} NOT_FOUND')
                exit(-1)
            print(f'[QUERY_VALUE] error: {ret}')
            exit(-1)
        print(f'[QUERY_VALUE] value_len: {value_len.value}')
        if value_type.value == REG_BINARY:
            print(f'[QUERY_VALUE] REG_BINARY: {name}')
            self._get_binary(name, value_len.value)

        elif value_type.value == REG_DWORD:
            print(f'[QUERY_VALUE] REG_DWORD: {name}')
            self._get_dword(name)
        else:
            assert (1 == 0)

    def _get_dword(self, name, size=4):
        dword_type = BYTE * size
        data = dword_type()
        ret = self.reg_queryvalue(self.h_key, LPCWSTR(name), 0, 0, data, byref(DWORD(size)))
        try:
            assert (ret == 0)
        except AssertionError as e:
            print(f'[GET_DWORD] error: {ret}')
            exit(-1)
        data = unpack('<I', bytes(map(lambda x: x % 0x100, data)))[0]
        print(f'[GET_DWORD]  data: 0x{data:08x}')

    def _get_binary(self, name, size):
        binary_type = BYTE * size
        data = binary_type()
        ret = self.reg_queryvalue(self.h_key, LPCWSTR(name), 0, 0, data, byref(DWORD(size)))
        try:
            assert (ret == 0)
        except AssertionError as e:
            print(f'[GET_BINARY] error: {ret}')
            exit(-1)
        data = bytes(map(lambda x: x % 0x100, data))
        print(f'[GET_BINARY] data: {data}')

    def filetime_to_datetime(self, filetime):
        t = filetime.dwHighDateTime << 32 | filetime.dwLowDateTime
        s, ns100 = divmod(t - EPOCH_AS_FILETIME, HUNDREDS_OF_NS)
        # tz_utc_8 = timezone(timedelta(hours=8))
        loacl_time = datetime.fromtimestamp(s).replace(microsecond=(ns100 // 10))
        return loacl_time


