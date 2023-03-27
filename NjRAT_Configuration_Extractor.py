import re
import sys

pattern = b'\x57\x52\x4B\x00\x6D\x61\x69\x6E'
with open(sys.argv[1], 'rb') as f:
    data = f.read()
    match = re.search(pattern, data)
    if match:
        print(f"Pattern found at byte offset {match.start()}")
        config = [] 
        offset = match.start()
        f.seek(offset+ 11)
        unicode_data = f.read(315)
        
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
        for i in range(0,12):
            print(config[i])

        
    else:
        print("Configuration offset not found")