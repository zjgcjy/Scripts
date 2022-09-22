# coding:utf-8
__author__ = "zjgcjy"

import ctypes


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ('wProcessorArchitecture', ctypes.c_uint16),
        ('wReserved', ctypes.c_uint16),
        ('dwPageSize', ctypes.c_uint32),
        ('lpMinimumApplicationAddress', ctypes.c_void_p),
        ('lpMaximumApplicationAddress', ctypes.c_void_p),
        ('dwActiveProcessorMask', ctypes.c_ulong),
        ('dwNumberOfProcessors', ctypes.c_uint32),
        ('dwProcessorType', ctypes.c_uint32),
        ('dwAllocationGranularity', ctypes.c_uint32),
        ('wProcessorLevel', ctypes.c_uint16),
        ('wProcessorRevision', ctypes.c_uint16),
    ]


PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_AMD64 = 9


def IsSystem32():
    GetNativeSystemInfo = ctypes.windll.kernel32.GetNativeSystemInfo
    if GetNativeSystemInfo == 0:
        return False
    sys_info = SYSTEM_INFO()
    GetNativeSystemInfo(ctypes.byref(sys_info))
    if sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL:
        return True
    elif sys_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64:
        return False
    else:
        return False


def main():
    if IsSystem32():
        print('os: i386')
    else:
        print('os: amd64')


if __name__ == '__main__':
    main()
