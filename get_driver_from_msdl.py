# coding:utf-8
__author__ = "zjgcjy"

import argparse
import pefile
import requests
import sys


class driver():
    def __init__(self, driver, sign=''):
        self.driver = driver
        self.pe = None
        self.sign = sign
        path_prefix = 'C:/Windows/System32/drivers/'
        self.url = 'https://msdl.microsoft.com/download/symbols'
        if sign != '':
            return
        try:
            self.pe = pefile.PE(path_prefix + self.driver, fast_load=True)
        except FileNotFoundError:
            sys.exit()
        self.pe.parse_data_directories()

    def download(self):
        self.url = f'{self.url}/{self.driver}/{self.sign}/{self.driver}'
        print(f'download from {self.url}')
        file = requests.get(self.url, timeout=60)
        if file.status_code == 200:
            with open(self.driver, 'wb') as f:
                f.write(file.content)
            print('download succeed')
        elif file.status_code == 404:
            print('download failed')


def get_driver_from_sign():
    parser = argparse.ArgumentParser(description='Download driver from Microsoft server')
    parser.add_argument('driver', type=str, help='driver name')
    parser.add_argument('sign', type=str, help='driver signature')
    parser.add_argument('--path', type=str, default='./', help='driver path')

    args = parser.parse_args()
    sys = driver(args.driver, args.sign)
    sys.download()


if __name__ == '__main__':
    get_driver_from_sign()
