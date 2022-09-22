# coding:utf-8
__author__ = "zjgcjy"

import argparse
import binascii
import capstone


def disasm(sc, mode=64):
    code = binascii.a2b_hex(sc)
    if mode == 32:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(code, 0x1000):
        print(f'0x{i.address:04x}: {i.mnemonic}\t{i.op_str}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='disassemble shellcode')
    parser.add_argument('sc', type=str, help='shellcode')
    parser.add_argument('--arch', type=str, default='64', help='architecture')
    args = parser.parse_args()

    disasm(args.sc, args.arch)
