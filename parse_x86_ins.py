# coding:utf-8

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
    return


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
    return


disasm32 = lambda x: disassemble(x, False)
disasm64 = lambda x: disassemble(x, True)


def parse_nnn(code, p, prefix, log=False):
    opcode = code[p]
    value = code[p + 1]

    mod = (value >> 6) & 0x3
    nnn = (value >> 3) & 0x7
    rm = (value >> 0) & 0x7
    if log:
        print(f"[NNN]->opcode: {opcode:02x}, nnn: {nnn:03b}, rm: {rm:03b}")
    size = 0

    data = (opcode, nnn)
    match data:
        case (0xC6, 0b000):  # MOV Eb, Ib
            size = parse_modrm(code, p + 1, prefix, log)
            size += 1
        case (0xC7, 0b000):  # MOV Ev, Lz
            size = parse_modrm(code, p + 1, prefix, log)
            if (prefix & PRE_OS) != 0:
                size += 2
            else:
                size += 4
        case (
            (0xFF, 0b010)  # near CALL Ev
            | (0xFF, 0b110)  # PUSH Ev
            | (0xFF, 0b100)  # near JMP Ev
        ):
            size = parse_modrm(code, p + 1, prefix, log)
        case _:
            raise Exception(f"invalid nnn opcode: {opcode:02x}, nnn: {nnn:03b}")
    return size


def parse_modrm(code, p, prefix, log=False):
    value = code[p]
    mod = (value >> 6) & 0x3
    reg = (value >> 3) & 0x7
    rm = (value >> 0) & 0x7
    if log:
        print(f"[MODRM]->mod: {mod:02b}, reg: {reg:03b}, rm: {rm:03b}")
    size = 0
    if (prefix & PRE_AS) != 0:
        match mod:
            case 0b00:
                size = 1
                if rm == 0b110:  # disp16
                    size += 2
            case 0b01:
                size = 1 + 1  # disp8
            case 0b10:
                size = 1 + 2  # disp16
            case 0b11:
                size = 1
    else:
        match mod:
            case 0b00:
                size = 1
                if rm == 0b100:  # [--][--]
                    size += parse_sib(code[p + 1], mod, log)
                elif rm == 0b101:  # disp32
                    size += 4
            case 0b01:
                size = 1 + 1  # disp8
                if rm == 0b100:  # [--][--]
                    size += parse_sib(code[p + 1], mod, log)
            case 0b10:
                size = 1 + 4  # disp32
                if rm == 0b100:  # [--][--]
                    size += parse_sib(code[p + 1], mod, log)
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
        print(
            f"[SIB]->mod: {mod:02b}, base: {base:03b}, index: {index:03b}, scale: {scale:02b}"
        )
    size = 1
    if base == 0b101:
        if mod == 0b00:
            size += 4
    return size


PRE_NP = 0x00
PRE_LK = 0x01
PRE_NE = 0x02
PRE_RE = 0x04
PRE_SG = 0x08
PRE_OS = 0x10
PRE_AS = 0x20


def parse_prfix(code, p, log=False):
    length = 0
    prefix = PRE_NP
    while True:
        opcode = code[p + length]
        match opcode:
            case 0xF0:  # LOCK
                prefix |= PRE_LK
            case 0xF2:  # REPNE
                prefix |= PRE_NE
            case 0xF3:  # REP/REPE
                prefix |= PRE_RE
            case (
                0x26  # ES
                | 0x2E  # CS
                | 0x36  # SS
                | 0x3E  # DS
                | 0x64  # FS
                | 0x65  # GS
            ):
                prefix |= PRE_SG
            case 0x66:  # Operand Size
                prefix |= PRE_OS
            case 0x67:  # Address Size
                prefix |= PRE_AS
            case _:
                break
        length += 1
        if length > 0xF:
            raise Exception(f"invalid prefix")
    if log:
        print(f"[PREFIX]->prefix: 0x{prefix:02x}, length: {length}")
    return length, prefix


def parse(code, is_x64=False, log=False):
    if log:
        print(f"[PARSE] {code}:")
    length = len(code)
    p = 0
    ins_length = 0
    while p < length:
        prefix = 0
        if code[p] in (
            0xF0,
            0xF2,
            0xF3,
            0x26,
            0x2E,
            0x36,
            0x3E,
            0x64,
            0x65,
            0x66,
            0x67,
        ):
            ins_length, prefix = parse_prfix(code, p, log)
            p += ins_length
        match code[p]:
            case 0x0F:
                raise Exception(f"unsupport two opcode")
            case (
                0x50  # PUSH rAX/r8
                | 0x51  # PUSH rCX/r9
                | 0x52  # PUSH rDX/r10
                | 0x53  # PUSH rBX/r11
                | 0x54  # PUSH rSP/r12
                | 0x55  # PUSH rBP/r13
                | 0x56  # PUSH rSI/r14
                | 0x57  # PUSH rDI/r15
            ):
                ins_length += 1
            case (
                0x6A  # PUSH Ib
                | 0xB0  # MOV AL/R8B, Ib
                | 0xB1  # MOV CL/R9B, Ib
                | 0xB2  # MOV DL/R10B, Ib
                | 0xB3  # MOV BL/R11B, Ib
                | 0xB4  # MOV AH/R12B, Ib
                | 0xB5  # MOV CH/R13B, Ib
                | 0xB6  # MOV DH/R14B, Ib
                | 0xB7  # MOV BH/R15B, Ib
                | 0xEB  # JMP short Jb
            ):
                ins_length = 1
                ins_length += 1
            case (
                0x88  # MOV Eb, Gb
                | 0x89  # MOV Ev, Gv
                | 0x8A  # MOV Gb, Eb
                | 0x8B  # MOV Gv, Ev
            ):
                ins_length += 1
                ins_length += parse_modrm(code, p + 1, prefix, log)
            case (
                0x68  # PUSH Iz
                | 0xA0  # MOV AL, Ob
                | 0xA1  # MOV rAX, Ov
                | 0xA2  # MOV Ob, AL
                | 0xA3  # MOV Ov, rAX
                | 0xE8  # CALL near Jz
                | 0xE9  # JMP near Jz
            ):
                ins_length += 1
                ins_length += 4
            case (
                0xB8  # MOV rAX/R8, Iv
                | 0xB9  # MOV rCX/R9, Iv
                | 0xBA  # MOV rDX/R10, Iv
                | 0xBB  # MOV rBX/R11, Iv
                | 0xBC  # MOV rSP/R12, Iv
                | 0xBD  # MOV rBP/R13, Iv
                | 0xBE  # MOV rSI/R14, Iv
                | 0xBF  # MOV rDI/R15, Iv
            ):
                ins_length += 1
                if (prefix & PRE_OS) != 0:
                    ins_length += 2
                else:
                    ins_length += 4
            case 0xC6 | 0xC7 | 0xFF:  # Grp 11 1A  # Grp 11 1A  # Grp 5 1A
                ins_length += 1
                ins_length += parse_nnn(code, p, prefix, log)
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

    test32(b"push ax")
    test32(b"push dword ptr[ax]")
    test32(b"push word ptr[ax]")
    test32(b"push word ptr [0x11223344]")
    test32(b"mov word ptr[eax+eax], ax")
    test32(b"mov dword ptr[bx+si], eax")
    test32(b"mov dword ptr [di], eax")
    test32(b"mov word ptr [di], ax")
    test32(b"mov word ptr[bx+si], ax")
    test32(b"mov word ptr[0x100], ax")
    test32(b"mov word ptr [0x90909090], ax")
    test32(b"mov dword ptr[ax], 1")
    test32(b"mov ax, 1")
    test32(b"mov word ptr [0x11223344], ax")
    test32(b"mov word ptr [0x11223344], 0x1")
    test32(b"mov word ptr cs:[1], 1")


def main():
    try:
        test32all()
    except Exception as e:
        print(f"ERROR! {e}")


main()

# code=b"\x67\x89\x00\x90"
# disasm32(code)
# parse(code, log=True)

# asm32(b"mov ebp, esp;")
