# coding:utf-8
__author__ = "zjgcjy"

import argparse
import pefile
import requests
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
        for directory in self.pe.DIRECTORY_ENTRY_DEBUG:
            debug_entry = directory.entry
            # print(debug_entry)
            if hasattr(debug_entry, 'PdbFileName'):
                pdb_file = debug_entry.PdbFileName[:-1].decode('ascii')
                guid = f'{debug_entry.Signature_Data1:08x}'
                guid += f'{debug_entry.Signature_Data2:04x}'
                guid += f'{debug_entry.Signature_Data3:04x}'
                guid += f'{int.from_bytes(debug_entry.Signature_Data4, byteorder="big"):016x}'
                guid = guid.upper()
                self.url = f'{self.url}/{pdb_file}/{guid}{debug_entry.Age:x}/{pdb_file}'
                print(f'download from {self.url}')

    def download(self):
        file = requests.get(self.url, timeout=60)
        if file.status_code == 200:
            with open(self.driver[:-3] + 'pdb', 'wb') as f:
                f.write(file.content)
            print('download succeed')
        elif file.status_code == 404:
            print('download failed')


def get_pdb():
    parser = argparse.ArgumentParser(description='Download pdb from Microsoft server')
    parser.add_argument('driver', type=str, help='driver name')
    parser.add_argument('--path', type=str, default='./', help='driver path')
    args = parser.parse_args()

    sys = driver(args.driver, args.path)
    sys.parse_sign()
    sys.download()


if __name__ == '__main__':
    get_pdb()
