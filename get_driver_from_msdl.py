#coding:utf-8
__author__ = "zjgcjy"
import pefile
import requests
import sys

class driver():
    def __init__(self, driver, sign = ''):
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

    def parse_sign(self):
        timestamp = f'{self.pe.FILE_HEADER.TimeDateStamp:08x}'
        imagesize = f'{self.pe.OPTIONAL_HEADER.SizeOfImage:x}'
        self.sign = timestamp + imagesize

    def download(self):
        self.url = f'{self.url}/{self.driver}/{self.sign}/{self.driver}'
        file = requests.get(self.url, timeout=60)
        if file.status_code == 200:
            with open(self.driver, 'wb') as f:
                f.write(file.content)
            print('download succeed')
        elif file.status_code == 404:
            print('download failed')

def get_sign_from_driver():
    sys = driver('dxgkrnl.sys')
    sys.parse_sign()
    print(sys.sign)

def get_driver_from_sign():
    sys = driver('dxgkrnl.sys', 'EDC1425F479000')
    sys.download()

if __name__ == '__main__':
    get_sign_from_driver()

    get_driver_from_sign()