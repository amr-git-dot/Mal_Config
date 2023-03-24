import binascii
import pefile
import codecs
import sys

# Sign extend function
def Sign_Extend(x,b):
    m = (1<<(b - 1))
    x = x & ((1 << b) - 1)
    return ((x^m)-m)

def custome_decryptor(data, key):

    x = 0
    i = 0
    S = [0]* 256

    while(True):
        S[i] = x
        i = x+1
        x = i
        if(x >= 256):
            break

    x = i = j = 0
    
    
    while(True):
        j = (j + S[x] + key[(x % 250)]) % 256
        S[x] = (S[x] ^ S[j]) % 256
        (S[j]) = (S[j] ^ S[i]) %256
        (S[i]) = (S[i] ^ S[j]) %256

        x = i +1
        i = x
        if(x >= 256):
            break

    decrypted = []
    x = y = j = k = 0
    cypher = 0

    while(True):
        var_1 = (j+1) % 256
        x = var_1
        k = (var_1 % 256)
        var_k1 = (S[k] % 256)
        y = (y + Sign_Extend(var_k1,8))
        var_k = Sign_Extend(var_k1,8)
        S[k] = S[y % 256] % 256
        k = (y %256)
        var_temp = Sign_Extend((S[y % 256] % 256),8) % 256
        S[k] = var_k1 % 256
        k = y
        var_2 = (x << 5)
        var_3 = (k >> 3)
        var_4 = (x >> 3)
        F = ((var_2^var_3)%256)
        t_3 = Sign_Extend((S[F] % 256),8)
        var_5 = (y << 5)
        var_6 = (var_4 ^ var_5)
        var_7 = var_temp
        t_1 = Sign_Extend(S[var_6 % 256],8) % 256
        t_2 = t_3 + t_1
        t_4 = var_k
        N = 0xFFFFFFAA
        t_5 = (t_2 ^ N)
        t_6= (t_4+var_7)
        t_7 = (t_5 % 256)
        t_8 = (t_6% 256)
        t_9 = ((S[t_8] + S[t_7]) % 256)
        t_10 = (y + var_7)
        t_11 = (t_9 ^ S[t_10 % 256] % 256) %256
        decrypted.append((data[cypher] ^ t_11) % 256)
        x = x+1
        j = x
        cypher = cypher + 1
        if (cypher >= len(data)):
            break
    return bytes(decrypted)



def get_section_data(filename):
    pe = pefile.PE(filename)
    for section in pe.sections:
        if '.bss' in section.Name.decode(encoding='utf-8').rstrip('x00'):
            return(section.get_data(section.VirtualAddress, section.SizeOfRawData))


def run():

    filename= sys.argv[1]
    data_encoded_extracted  = get_section_data(filename)

    data_offset = 0 


    data_off = 0x0
    if (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' in data_encoded_extracted[data_offset:]):

        data_off = (data_encoded_extracted[int(data_offset):]).index(b'\x00\x00\x00\x00\x00\x00\x00\x00')

    encrypted_data = data_encoded_extracted[data_offset:data_offset+data_off]
    


    Key_ = encrypted_data[4:54]

    data_ = encrypted_data[54:]

    Key_ += bytes([0] * 200)
    

    decrypted_ = custome_decryptor(data_, Key_)


    print("\nC2: %s" % (''.join(map(chr, decrypted_[1:27]))))



def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]}.py <filename>")
        return
    run()

if __name__ == '__main__':
    main()