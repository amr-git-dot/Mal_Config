import sys
import json
import binascii

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python BlackCat_config_Extractor.py BlackCat_Sample")
    else:
        try:
            file_path = sys.argv[1]
            with open(file_path, 'rb') as file:
                content = file.read()

            offset = content.find(binascii.unhexlify(b"7B22636F6E6669675F696422"))

            if offset == -1:
                print("\nunable to find configuration offset\n\n")
                sys.exit(1)

            cfg = content[offset: offset+8000].strip()

            config = json.loads(cfg.decode('utf-8'))
            print(config)

        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
