# coding:utf-8
__author__ = "zjgcjy"

import argparse
import pefile
import sys


class driver():
    def __init__(self, driver, path_prefix='C:/Windows/System32/drivers/'):
        self.driver = driver
        self.pe = None
        self.url = 'https://msdl.microsoft.com/download/symbols'
        try:
            self.pe = pefile.PE(path_prefix + self.driver, fast_load=True)
        except FileNotFoundError:
            print('Driver Not Found')
            sys.exit(-1)

    def parse_sign(self):
        self.pe.parse_data_directories()
        timestamp = f'{self.pe.FILE_HEADER.TimeDateStamp:08x}'
        imagesize = f'{self.pe.OPTIONAL_HEADER.SizeOfImage:x}'
        self.sign = timestamp + imagesize


def get_sign_from_driver():
    parser = argparse.ArgumentParser(description='Download driver from Microsoft server')
    parser.add_argument('driver', type=str, help='driver name')
    parser.add_argument('--path', type=str, default='./', help='driver path')
    args = parser.parse_args()

    sys = driver(args.driver, args.path)
    sys.parse_sign()
    print(f'sign: {sys.sign}')


if __name__ == '__main__':
    get_sign_from_driver()
