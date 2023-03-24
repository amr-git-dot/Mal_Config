import pefile
import sys

def ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def rc4_decrypt(ciphertext, key):
    S = ksa(key)
    keystream = prga(S)
    plaintext = bytearray()
    for c in ciphertext:
        plaintext.append(c ^ next(keystream))
    return bytes(plaintext)

if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]}.py <filename>")
        exit()

pe = pefile.PE(sys.argv[1])
bss_section = pe.sections[-1]
bss_start = bss_section.VirtualAddress
bss_end = bss_start + bss_section.Misc_VirtualSize

bss_data = pe.get_memory_mapped_image()[bss_start:bss_end]
key_length = 50
key = bss_data[4:key_length+4]

data_offset = 0 


data_off = 0x0
if (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' in bss_data[data_offset:]):

        data_off = (bss_data[int(data_offset):]).index(b'\x00\x00\x00\x00\x00\x00\x00\x00')
        

data = bss_data[key_length+4:140]

decrypted_data = rc4_decrypt(data, key)
try :
    print(decrypted_data.decode('utf-16-le'))

except:
    print(decrypted_data.decode('latin1'))
