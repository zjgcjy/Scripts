#coding:utf-8
__author__ = "zjgcjy"
import binascii
import ctypes
import pefile
import sys

# see ntimage.h 22621
IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE             = 0x00000001
IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE             = 0x00000002
IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER = 0x00000003
IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER  = 0x00000004
IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH      = 0x00000005
IMAGE_DYNAMIC_RELOCATION_ARM64X                        = 0x00000006
IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE             = 0x00000007
IMAGE_DYNAMIC_RELOCATION_MM_SHARED_USER_DATA_VA        = 0x7FFE0000
#IMAGE_DYNAMIC_RELOCATION_KI_USER_SHARED_DATA64        = 0xFFFFF78000000000UI64

class dvrt():
    def __init__(self, driver, path_prefix = 'C:/Windows/System32/drivers/'):
        self.driver_name = driver
        self.pe = None
        self.ptr = 0
        self.rva_list = []
        try:
            self.pe = pefile.PE(path_prefix + self.driver_name, fast_load=True)
        except FileNotFoundError:
            exit()
        self.pe.parse_data_directories()
        self.get_ori()

    def get_ori(self):
        for section in self.pe.sections:
            if section.Name != b'.reloc\x00\x00':
                continue
            self.ptr = self.pe.get_offset_from_rva(section.VirtualAddress)
            while self.get_dvrt_foa() not in [0x00, 0x01]:
                pass
            version = self.read_dword()
            size = self.read_dword()
            end = self.ptr + size
            print(f'version: 0x{version:02x}, size: 0x{size:08x}, end: 0x{end:08x}')
            while self.ptr < end:
                self.parse_dvrt()

    p16 = lambda self: self.pe.get_word_from_offset(self.ptr)
    p32 = lambda self: self.pe.get_dword_from_offset(self.ptr)
    p64 = lambda self: self.pe.get_qword_from_offset(self.ptr)

    def read_word(self):
        temp = self.p16(f)
        self.ptr += 2
        return temp

    def read_dword(self):
        temp = self.p32()
        self.ptr += 4
        return temp

    def read_qword(self):
        temp = self.p64()
        self.ptr += 8
        return temp

    def get_dvrt_foa(self):
        VirtualAddress = self.read_dword()
        if VirtualAddress == 0x01 or VirtualAddress == 0x0:
            self.ptr -= 4
            return VirtualAddress
        SizeOfBlock = self.read_dword()
        # print(f'VirtualAddress: 0x{VirtualAddress:08x}, SizeOfBlock: 0x{SizeOfBlock:08x}')
        self.ptr += SizeOfBlock - 8
        return VirtualAddress

    def parse_dvrt(self):
        Symbol = self.read_qword()
        BaseRelocSize = self.read_dword()
        print(f'ptr: 0x{self.ptr:08x}, Symbol: 0x{Symbol:02x}, BaseRelocSize: 0x{BaseRelocSize:08x}')
        stop = self.ptr + BaseRelocSize
        # TODO: win11 ntoskrnl!RtlPerformRetpolineRelocationsOnImageEx
        if Symbol == IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE:
            self.ptr = stop
            return
        while self.ptr < stop:
            VirtualAddress = self.read_dword()
            # print(f'VirtualAddress: 0x{VirtualAddress:08x})
            SizeOfBlock = self.read_dword()
            # print(f'SizeOfBlock: 0x{SizeOfBlock:08x})
            for i in range((SizeOfBlock - 8) // 4):
                item = self.read_dword()
                if Symbol == IMAGE_DYNAMIC_RELOCATION_GUARD_IMPORT_CONTROL_TRANSFER:
                    va = VirtualAddress + (item & 0xfff)
                    self.rva_list.append((va, 12))
                elif Symbol == IMAGE_DYNAMIC_RELOCATION_GUARD_INDIR_CONTROL_TRANSFER:
                    va = VirtualAddress + (item & 0xfff)
                    if (item >> 12) & 0x01:
                        self.rva_list.append((va, 6))
                    else:
                        self.rva_list.append((va, 5))
                elif Symbol == IMAGE_DYNAMIC_RELOCATION_GUARD_SWITCHTABLE_BRANCH:
                    va = VirtualAddress + (item & 0xfff)
                    self.rva_list.append((va, 5))
                elif Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X:
                    pass
                elif Symbol == IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE:
                    pass
                else:
                    assert(1 == 0)
                    sys.exit()

def main():
    obj = dvrt('dxgkrnl.sys', './')

if __name__ == '__main__':
    main()