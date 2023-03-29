import sys
import re

if len(sys.argv) < 2:
    print("Usage: python script.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

with open(filename, "rb") as f:
    cont = f.read()

match = re.search(b"\x47\x65\x74\x57\x69\x6E\x64\x6F\x77\x54\x65\x78\x74.*\x00\x00", cont)

print(f"match found at {match.start()}")

nullmatch = re.search(b'\x00\x00', cont[match.start():])

print(f"null match at {nullmatch.start()+ match.start()}")
unicode_offset = nullmatch.start()+ match.start()
unicode_data = cont[unicode_offset:300+unicode_offset]

config = []
for data in unicode_data :
    data = data.to_bytes(1, byteorder="little")
    
    if data > b'\x00' and data < b'\x2E' and data != b'1B' and data != b'27':
        config.append("&")
    elif data < b'\x7F' and data > b'\x20':
        try :
            config.append(data.decode("utf-8"))
        except:
            pass

config = ''.join(config)            
config = config.split("&")
for i in range(0,len(config)):
    print(config[i])
