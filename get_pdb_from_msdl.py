#coding:utf-8
__author__ = "zjgcjy"
import pefile
import requests

class driver():
    def __init__(self, driver, path_prefix = 'C:/Windows/System32/drivers/'):
        self.driver = driver
        self.pe = None
        self.url = 'https://msdl.microsoft.com/download/symbols'
        try:
            self.pe = pefile.PE(path_prefix + self.driver, fast_load=True)
        except FileNotFoundError:
            exit()


    def parse_sign(self):
        self.pe.parse_data_directories()
        for directory in self.pe.DIRECTORY_ENTRY_DEBUG:
            debug_entry = directory.entry
            #print(debug_entry)
            if hasattr(debug_entry, 'PdbFileName'):
                pdb_file = debug_entry.PdbFileName[:-1].decode('ascii')
                guid = f'{debug_entry.Signature_Data1:08x}'
                guid += f'{debug_entry.Signature_Data2:04x}'
                guid += f'{debug_entry.Signature_Data3:04x}'
                guid += f'{int.from_bytes(debug_entry.Signature_Data4, byteorder="big"):016x}'
                guid = guid.upper()
                self.url = f'{self.url}/{pdb_file}/{guid}{debug_entry.Age:x}/{pdb_file}'
                #print(url)

    def download(self):
        file = requests.get(self.url, timeout=60)
        if file.status_code == 200:
            with open(self.driver[:-3]+'pdb', 'wb') as f:
                f.write(file.content)
            print('download succeed')
        elif file.status_code == 404:
            print('download failed')

def get_pdb():
    sys = driver('dxgkrnl.sys', './')
    sys.parse_sign()
    sys.download()

if __name__ == '__main__':
    get_pdb()