import os
import struct
import hashlib
import logging
from Crypto.Cipher import AES

logging.basicConfig(level=logging.DEBUG)
console = logging.getLogger('console')

def hex_dump(data, sep=':'):
    return sep.join([f'{b:02x}' for b in data])


def hash_MD5(input_data):
    return hashlib.md5(input_data).digest()


def aesDecrypt(tmpArr, xArr):
    cipher = AES.new(tmpArr, AES.MODE_ECB)
    return cipher.decrypt(xArr)


class XignLog:
    def __init__(self):
        self.sign_header = 0
        self.sign_type = 0
        self.unk_buffer = bytearray(16)
        self.key = bytearray(12)
        self.after_key = bytearray(4)
        self.hash = bytearray(4)
        self.after_hash0 = 0
        self.after_hash1 = 0
        self.after_hash2 = 0
        self.v_const = 0
        self.fff = bytearray(16)
        self.second_buffer = bytearray(240)
        self.sign_tail = 0
        self.junk = 0
        self.log_count = 0

def main():
    print("Xigncode Log Unpacker\nmade with python by hendyanwilly\n")

    input_file_path = input("xigncode.log dosyasi belirtiniz: ").strip()

    if not os.path.exists(input_file_path):
        console.error("Input file does not exist: {}".format(input_file_path))
        return 1

    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_file_name = os.path.splitext(os.path.basename(input_file_path))[0] + "_unpacked.txt"
    output_file_path = os.path.join(base_dir, output_file_name)

    print(f"Unpacking {input_file_path}...")

    arrXign = []

    with open(input_file_path, 'rb') as file:
        while True:
            data = file.read(320)
            if not data:
                break
            tmp_log = XignLog()
            try:
                tmp_log_bytes = struct.unpack(
                    'I I 16s 12s 4s 4B B B H I 16s 240s I I I', data
                )

                (tmp_log.sign_header,
                 tmp_log.sign_type,
                 tmp_log.unk_buffer,
                 tmp_log.key,
                 tmp_log.after_key,
                 tmp_log.hash[0],
                 tmp_log.hash[1],
                 tmp_log.hash[2],
                 tmp_log.hash[3],
                 tmp_log.after_hash0,
                 tmp_log.after_hash1,
                 tmp_log.after_hash2,
                 tmp_log.v_const,
                 tmp_log.fff,
                 tmp_log.second_buffer,
                 tmp_log.sign_tail,
                 tmp_log.junk,
                 tmp_log.log_count) = tmp_log_bytes
                
                #print(tmp_log_bytes)

                arrXign.append(tmp_log)
            except struct.error as e:
                console.error(f"Error unpacking data: {e}")
                return 1

    print(f"{output_file_path} 'dosyasina unpack ediliyor...")

    with open(output_file_path, 'wb') as output_file:
        for tmp_log in arrXign:
            try:
                hash_vector = bytes(tmp_log.hash)
                tmpArr = hash_MD5(hash_vector)
                decrypted_buffer = aesDecrypt(tmpArr, tmp_log.second_buffer)
                output_file.write(decrypted_buffer)
            except ValueError as e:
                console.error(f"Error decrypting data: {e}")
                return 1

    print("Tamamlandi!")


if __name__ == '__main__':
    main()
