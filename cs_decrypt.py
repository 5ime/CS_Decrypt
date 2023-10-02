import hmac
import base64
import hashlib
import hexdump
import binascii
import javaobj.v2 as javaobj
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

file_path = ".cobaltstrike.beacon_keys"
encode_data = "PcdKQuOPNdlyJMzB9IdLt3FyYJK5ooh2hagReIiCPX3enVE8IUWclknGedXTxAW6Seq0pUuqbA3d6h59a43lQH+2l4egkNL/aTuaMndjIcrM7HFHDQSumu/VoeG+O9vNB63W6YtJDidYt+SjFCZPOjcTblEU+CDGzN4xNO+bh1s="
encrypt_data = "000000c0cc3581241436712c84735d65bf5faa7ac3da1ac1b7583bea79d54c00c517866397786623818cb11af81460bf963e7da0be7bd4c8afc27d4d7efb783ce7d3a889d14dada2a851f0b2919af4242efdc0e43ad80053b5d7ffc933416ec0861d24280f6d80bf6baf39264c534296b81635f8b2ce9824f03839f1aa4a2941186bed40820296e5637b168ad6bac0801c6c79e2c63f0319e9b12434854c0721cc34a323f044b630b2796478f6802590774d1a83f769fb1e2bfb1c577bfe02d958f5b41c"

def format_key(key_data):
    key_data = bytes(map(lambda x: x & 0xFF, key_data))
    formatted_key = f"-----BEGIN PRIVATE KEY-----\n"
    formatted_key += base64.encodebytes(key_data).decode()
    formatted_key += f"-----END PRIVATE KEY-----"
    return formatted_key

def decrypt(encrypted_data, iv_bytes, signature, shared_key, hmac_key):
    if hmac.new(hmac_key, encrypted_data, digestmod="sha256").digest()[:16] != signature:
        print("message authentication failed")
        return

    cipher = AES.new(shared_key, AES.MODE_CBC, iv_bytes)
    return cipher.decrypt(encrypted_data)

with open(file_path, "rb") as fd:
    pobj = javaobj.load(fd)

PRIVATE_KEY = format_key(pobj.array.value.privateKey.encoded.data)
private_key = RSA.import_key(PRIVATE_KEY.encode())
cipher = PKCS1_v1_5.new(private_key)
ciphertext = cipher.decrypt(base64.b64decode(encode_data), 0)

if ciphertext[0:4] == b'\x00\x00\xBE\xEF':
    raw_aes_keys = ciphertext[8:24]
    raw_aes_hash256 = hashlib.sha256(raw_aes_keys).digest()
    aes_key = raw_aes_hash256[0:16]
    hmac_key = raw_aes_hash256[16:]

SHARED_KEY = binascii.unhexlify(aes_key.hex())
HMAC_KEY = binascii.unhexlify(hmac_key.hex())

encrypt_data = base64.b64encode(bytes.fromhex(encrypt_data)).decode()
encrypt_data = base64.b64decode(encrypt_data)
encrypt_data_length = int.from_bytes(encrypt_data[:4], byteorder='big', signed=False)
encrypt_data_l = encrypt_data[4:]
data1 = encrypt_data_l[:encrypt_data_length-16]
signature = encrypt_data_l[encrypt_data_length-16:encrypt_data_length]
iv_bytes = b"abcdefghijklmnop"

dec = decrypt(data1, iv_bytes, signature, SHARED_KEY, HMAC_KEY)
print("AES key: {}".format(aes_key.hex()))
print("HMAC key: {}".format(hmac_key.hex()))
print(dec[12:int.from_bytes(dec[4:8], byteorder='big', signed=False)])
print(hexdump.hexdump(dec))
