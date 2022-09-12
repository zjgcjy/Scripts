#coding:utf-8
__author__ = "zjgcjy"
import binascii
import ctypes
import pefile

class dvrt():
    def __init__(self, driver):
        self.driver_name = driver
        self.pe = None
        self.ptr = 0
        self.rva_list = []
        path_prefix = 'C:/Windows/System32/drivers/'
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
            print('version: 0x%04x' % version)
            size = self.read_dword()
            print('size: 0x%08x\n' % size)
            end = self.ptr + size
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
        #print('VirtualAddress: 0x%08x, SizeOfBlock: 0x%08x'% (VirtualAddress, SizeOfBlock))
        self.ptr += SizeOfBlock - 8
        return VirtualAddress

    def parse_dvrt(self):
        Symbol = self.read_qword()
        BaseRelocSize = self.read_dword()
        print('Symbol: 0x%04x, BaseRelocSize: 0x%08x' % (Symbol, BaseRelocSize))
        stop = self.ptr - 8 + BaseRelocSize
        while self.ptr < stop:
            VirtualAddress = self.read_dword()
            # print('VirtualAddress: 0x%08x' % VirtualAddress)
            SizeOfBlock = self.read_dword()
            # print('SizeOfBlock: 0x%08x' % SizeOfBlock)
            for i in range((SizeOfBlock - 8) // 4):
                item = self.read_dword()
                if Symbol == 3:
                    va = VirtualAddress + (item & 0xfff)
                    self.rva_list.append((va, 12))
                elif Symbol == 4:
                    va = VirtualAddress + (item & 0xfff)
                    if (item >> 12) & 0x01:
                        self.rva_list.append((va, 6))
                    else:
                        self.rva_list.append((va, 5))
                elif Symbol == 5:
                    va = VirtualAddress + (item & 0xfff)
                    self.rva_list.append((va, 5))
                else:
                    assert(1 == 0)
                    exit()

def main():
    obj = dvrt('dxgkrnl.sys')

if __name__ == '__main__':
    main()