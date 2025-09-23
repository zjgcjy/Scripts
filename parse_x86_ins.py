#coding:utf-8

from capstone import *
from keystone import *

def assemble(asm_code, is_x64=False, log=False):
    mode = KS_MODE_32
    if is_x64:
        mode = KS_MODE_64
    try:
        ks = Ks(KS_ARCH_X86, mode)
        code, _ = ks.asm(asm_code)
        code = "".join(map(lambda x: f"{x:02x}", code))
        if log:
            print(f"\n[ASSEMBLE] {asm_code}: {code}")
        return code, len(code) // 2
    except KsError as e:
        raise Exception(f"error: {e}")

asm32 = lambda x, log=False: assemble(x, False, log)
asm64 = lambda x, log=False: assemble(x, True, log)

def disassemble(code, is_x64=False):
    print(f"[DISASSEMBLE] {code}:")
    mode = CS_MODE_32
    if is_x64:
        mode = CS_MODE_64
    cs = Cs(CS_ARCH_X86, mode)
    for insn in cs.disasm(code, 0x1000):
        print(f"\tsize:{insn.size} {insn.mnemonic} {insn.op_str}")

disasm32 = lambda x: disassemble(x, False)
disasm64 = lambda x: disassemble(x, True)



def parse_nnn(code, p, log=False):
    opcode = code[p]
    value = code[p+1]

    mod = (value >> 6) & 0x3
    nnn = (value >> 3) & 0x7
    rm = (value >> 0) & 0x7
    if log:
        print(f"[NNN]->mod: {mod:02b}, nnn: {nnn:03b}, rm: {rm:03b}")
    size = 0

    data = (opcode, nnn)
    match data:
        case (0xc6, 0b000): # MOV Eb, Ib
            size = parse_modrm(code, p+1, log)
            size += 1
        case (0xc7, 0b000): # MOV Ev, Lz
            size = parse_modrm(code, p+1, log)
            size += 4
        case (
            (0xff, 0b010) # near CALL Ev
            | (0xff, 0b110) # PUSH Ev
            | (0xff, 0b100) # near JMP Ev
        ):
            size = parse_modrm(code, p+1, log)
        case _:
            raise Exception(f"invalid nnn opcode: {opcode:02x}, nnn: {nnn:03b}")
    return size

def parse_modrm(code, p, log=False):
    value = code[p]
    mod = (value >> 6) & 0x3
    reg = (value >> 3) & 0x7
    rm = (value >> 0) & 0x7
    if log:
        print(f"[MODRM]->mod: {mod:02b}, reg: {reg:03b}, rm: {rm:03b}")
    size = 0
    match mod:
        case 0b00:
            size = 1
            if rm == 0b100:
                size += parse_sib(code[p+1], mod, log)
            elif rm == 0b101:
                size += 4
        case 0b01:
            size = 1+1  # include disp in sib
            if rm == 0b100:
                size += parse_sib(code[p+1], mod, log)
        case 0b10:
            size = 1+4  # include disp in sib 
            if rm == 0b100:
                size += parse_sib(code[p+1], mod, log)
        case 0b11:
            size = 1
    if size == 0:
        raise Exception(f"invalid modrm")
    return size

def parse_sib(value, mod, log=False):
    base = (value >> 0) & 0x7
    index = (value >> 3) & 0x7
    scale = (value >> 6) & 0x3
    if log:
        print(f"[SIB]->mod: {mod:02b}, base: {base:03b}, index: {index:03b}, scale: {scale:02b}")
    size = 1
    if base == 0b101:
        if mod == 0b00:
            size += 4
    return size


def parse(code, is_x64=False, log=False):
    if log:
        print(f"[PARSE] {code}:")
    length = len(code)
    p = 0
    ins_length = 0
    while p < length:
        match code[p]:
            case 0x0f:
                raise Exception(f"unsupport two opcode")
            case (
                0x50 # PUSH rAX/r8
                | 0x51 # PUSH rCX/r9
                | 0x52 # PUSH rDX/r10
                | 0x53 # PUSH rBX/r11
                | 0x54 # PUSH rSP/r12
                | 0x55 # PUSH rBP/r13
                | 0x56 # PUSH rSI/r14
                | 0x57 # PUSH rDI/r15
            ):
                ins_length = 1
            case (
                0x6a # PUSH Ib
                | 0xb0 # MOV AL/R8B, Ib
                | 0xb1 # MOV CL/R9B, Ib
                | 0xb2 # MOV DL/R10B, Ib
                | 0xb3 # MOV BL/R11B, Ib
                | 0xb4 # MOV AH/R12B, Ib
                | 0xb5 # MOV CH/R13B, Ib
                | 0xb6 # MOV DH/R14B, Ib
                | 0xb7 # MOV BH/R15B, Ib
                | 0xeb # JMP short Jb
            ):
                ins_length = 1
                ins_length += 1
            case (
                0x00 # ADD Eb, Gb
                | 0x01 # ADD Ev, Gv
                | 0x02 # ADD Gb, Eb
                | 0x03 # ADD Gv, Ev
                | 0x28 # SUB Eb, Gb
                | 0x29 # SUB Ev, Gv
                | 0x2a # SUB Gb, Eb
                | 0x2b # SUB Gv, Ev
                | 0x88 # MOV Eb, Gb
                | 0x89 # MOV Ev, Gv
                | 0x8a # MOV Gb, Eb
                | 0x8b # MOV Gv, Ev
            ): 
                ins_length = 1
                ins_length += parse_modrm(code, p+1, log)
            case (
                0x68 # PUSH Iz
                | 0xa0 # MOV AL, Ob
                | 0xa1 # MOV rAX, Ov
                | 0xa2 # MOV Ob, AL
                | 0xa3 # MOV Ov, rAX
                | 0xb8 # MOV rAX/R8, Iv
                | 0xb9 # MOV rCX/R9, Iv
                | 0xba # MOV rDX/R10, Iv
                | 0xbb # MOV rBX/R11, Iv
                | 0xbc # MOV rSP/R12, Iv
                | 0xbd # MOV rBP/R13, Iv
                | 0xbe # MOV rSI/R14, Iv
                | 0xbf # MOV rDI/R15, Iv
                | 0xe8 # CALL near Jz
                | 0xe9 # JMP near Jz
            ):
                ins_length = 1
                ins_length += 4
            case (
                0xc6 # Grp 11 1A
                | 0xc7 # Grp 11 1A
                | 0xff # Grp 5 1A
            ):
                ins_length = 1
                ins_length += parse_nnn(code, p, log)
            case _:
                raise Exception(f"unsupport opcode: {code[p]:02x}")
        if log:
            print(f"[INS]->ins_length: {ins_length}")
        p += ins_length
        return ins_length


def test32(x, log=False):
    print(f"[TEST] {x.decode()}", end="......")
    code, size = asm32(x, log=log)
    assert size == parse(bytes.fromhex(code), log=log, is_x64=False)
    print(f"ok")


def test32all():
    test32(b"mov al, bl")
    test32(b"mov eax, ecx")
    test32(b"mov dword ptr[ebp], eax")
    test32(b"mov eax, dword ptr [ebp+0x4]")
    test32(b"mov dword ptr [ebp+0x100000], eax")
    test32(b"mov dword ptr [edi+eax*4], eax")
    test32(b"mov eax, dword ptr [0x10000+edi+ecx*4]")
    test32(b"mov bl, byte ptr [esi+eax*4+0x33221100]")
    test32(b"mov eax, dword ptr[0x10]")
    test32(b"mov dword ptr [0x1000000], eax")
    test32(b"mov ebx, dword ptr [eax+0x44332211]")
    test32(b"mov bl, 0x12")
    test32(b"mov eax, 0x11223344")
    test32(b"mov byte ptr[bl], 0x12")
    test32(b"mov dword ptr[ecx], 0x12345678")
    test32(b"mov byte ptr [0x12345678], 0x90")
    test32(b"mov byte ptr [ecx+eax], 0x10")
    test32(b"mov dword ptr [esi+ecx*8], 0x12345678")
    test32(b"mov dword ptr [0x10000+edi], 0x12345678")
    test32(b"mov dword ptr [0x88888888+esi+eax*4], 0x12345678")
    test32(b"mov byte ptr [0x88+ebp+eax*4], 0xcc")
    test32(b"mov byte ptr [eax-0x6f6f6f70], 0x90")
    test32(b"mov byte ptr [eax*2-0x6f6f6f70], 0x90")
    test32(b"mov dword ptr [ebp+eax*8-0x6f6f6f70], 0x90909090")

    test32(b"push 0x1")
    test32(b"push 0x0100")
    test32(b"push 0x11223344")
    test32(b"push eax")
    test32(b"push ebp")
    test32(b"push [eax]")
    test32(b"push [ebp]")
    test32(b"push [0]")
    test32(b"push [ebp+0x4]")
    test32(b"push dword ptr [ebp+0x100000]")
    test32(b"push dword ptr [0x100000+ebp+ecx*4]")

    test32(b"jmp 50")
    test32(b"jmp 0x100000")
    test32(b"jmp eax")
    test32(b"jmp [ebp]")
    test32(b"jmp [eip+0x88888]")
    test32(b"jmp [0x100000+ebp+ecx*4]")
    test32(b"jmp [0x11223344]")

    test32(b"call 50")
    test32(b"call 0x100000")
    test32(b"call eax")
    test32(b"call [ebp]")
    test32(b"call [eip+0x88888]")
    test32(b"call [0x100000+ebp+ecx*4]")
    test32(b"call [0x11223344]")



def main():
    try:
        test32all()
    except Exception as e:
        print(f"ERROR! {e}")


main()

#code=b"\xea\x78\x56\x34\x21\x90\x90\x90\x90"
#disasm32(code)
# parse(code, log=True)

#asm32(b"mov ebp, esp;")

