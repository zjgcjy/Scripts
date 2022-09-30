# coding:utf-8
__author__ = "zjgcjy"

import ida_bytes as ib
import idc


class El():
    def __init__(self, base, name):
        self.buf = None
        self.size = None
        if not isinstance(base, int):
            raise TypeError("base must be num")
        if not isinstance(name, str):
            raise TypeError("name must be str")
        assert(ib.get_dword(base) == 1)
        self.base = base
        self.name = name

    def get_ctx(self):
        self.size = ib.get_dword(self.base + 4)
        print(f'size: {self.size:08x}')
        if ib.get_item_size(self.base + 8) == 1:
            self.buf = ib.get_bytes(self.base + 8, self.size)
            idc.make_array(self.base + 8, self.size)

    def dump(self):
        self.get_ctx()
        with open(self.name, 'wb') as f:
            f.write(self.buf)
        print('[OK]: ' + self.name)


def dump_test():
    El(0xaaaaaaaa, 'output.bin').dump()


if __name__ == '__main__':
    dump_test()
