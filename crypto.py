#Cipher AES
import hashlib

#Use bytes instead of text in PostgreSQL
from Crypto.Cipher import AES
class Cipher:
    def __init__(self):
        self.mode = None

    def encrypt(self,key,text:str)->str:pass
    def decrypt(self,key,text:str)->str:pass

class AESCipher(Cipher):
    def __init__(self):
        self.mode = AES.MODE_ECB

    def encrypt(self,key:bytes,text:bytes)->bytes:
        aes = AES.new(key, self.mode)
        #Aligment 16 byte
        if len(text)%16!=0:
            text = text+abs(len(text)%16-16)*b' '

        return aes.encrypt(text)

    def decrypt(self,key:bytes,text:bytes) -> bytes:
        aes = AES.new(key, self.mode)
        return aes.decrypt(text)


def CryptoAPI(code:int, key:bytes, data:bytes):
    aes = AESCipher()
    if isinstance(data, str) and len(data)==0:
        data = ' '*8

    match code:
        case 0: return str(aes.encrypt(key, data),encoding='windows-1256')
        case 1: return str(aes.decrypt(key, data),encoding='utf-8').strip()
        case _: return None