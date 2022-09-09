#coding:utf-8
__author__ = "zjgcjy"
import pefile
import requests

class driver():
    def __init__(self, driver):
        self.driver = driver
        self.pe = None
        self.sign = ''
        self.url = 'https://msdl.microsoft.com/download/symbols/dxgkrnl.sys/%s/dxgkrnl.sys'
        path_prefix = 'C:/Windows/System32/drivers/'
        try:
            self.pe = pefile.PE(path_prefix + self.driver, fast_load=True)
        except FileNotFoundError:
            exit()
        self.pe.parse_data_directories()

    def parse_sign(self):
        timestamp = self.pe.FILE_HEADER.TimeDateStamp
        imagesize = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.sign = hex(timestamp)[2:].upper().rjust(8, '0') + hex(imagesize)[2:].upper()

    def download(self):
        url = self.url % self.sign
        file = requests.get(url, timeout=60)
        if file.status_code == 200:
            with open(self.driver, 'wb') as f:
                f.write(file.content)
            print('download succeed')
        elif file.status_code == 404:
            print('download failed')

def main():
    sys = driver('dxgkrnl.sys')
    sys.parse_sign()
    sys.download()

if __name__ == '__main__':
    main()