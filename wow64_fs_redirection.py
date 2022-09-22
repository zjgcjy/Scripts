# coding:utf-8
__author__ = "zjgcjy"

import ctypes


class Wow64():
    def __init__(self):
        self.wow64_old_value = ctypes.c_uint32(0)
        self.iswow64 = ctypes.c_bool(False)

    def IsWow64Process(self):
        IsWow64Process = ctypes.windll.kernel32.IsWow64Process
        if IsWow64Process == 0:
            return False
        is_wow = ctypes.c_bool(False)
        IsWow64Process(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(is_wow))
        self.iswow64 = is_wow.value

    def Wow64Disable(self):
        Wow64DisableWow64FsRedirection = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
        if Wow64DisableWow64FsRedirection == 0:
            return False
        return Wow64DisableWow64FsRedirection(ctypes.byref(self.wow64_old_value))

    def Wow64Enable(self):
        Wow64RevertWow64FsRedirection = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
        if Wow64RevertWow64FsRedirection == 0:
            return False
        return Wow64RevertWow64FsRedirection(self.wow64_old_value)

    def init(self):
        self.IsWow64Process()
        if self.iswow64:
            self.Wow64Disable()

    def fini(self):
        if self.iswow64:
            self.Wow64Enable()


def main():
    fs = Wow64()
    fs.init()
    # do something else
    fs.fini()


if __name__ == '__main__':
    main()
