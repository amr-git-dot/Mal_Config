import clr
clr.AddReference("System.Reflection")
import System.Reflection
import base64
import sys

if len(sys.argv) != 2:
    print("Usage: python RedLine_Config_Extractor.py <File_Full_Path>")
    sys.exit(1)

file_path = sys.argv[1]

try:
    def decrypt(encrypted_string, key):
        decoded_data = base64.b64decode(encrypted_string)
        decrypted_chars = [chr(byte ^ ord(key[i % len(key)])) for i, byte in enumerate(decoded_data)]
        decrypted_text = ''.join(decrypted_chars)
        plaintext = base64.b64decode(decrypted_text)
        return plaintext.decode('utf-8')



    assembly = System.Reflection.Assembly.LoadFile(file_path)


    class_name = "EntryPoint"
    class_type = assembly.GetType(class_name)
    class_instance = System.Activator.CreateInstance(class_type)


    for type in assembly.GetTypes():
        if type.Name == "EntryPoint":
            fields = type.GetFields()
            if len(fields) == 0:
                print("Cannot Extract the configuration.")
            else:
                print("Sample configuration:")
                for field in fields:
                    field_value = field.GetValue(class_instance)
                    if field.Name == "IP":
                        Ip = field_value
                    if field.Name == "ID":
                        Id = field_value
                    if field.Name == "Message":
                        Message = field_value
                    if field.Name == "Key":
                        Key = field_value    

    print(f"IP : {decrypt(Ip,Key)}")
    print(f"ID : {decrypt(Id,Key)}")
    print(f"Message : {decrypt(Message,Key)}")
    print(f"Key : {Key}") 

except Exception as e:
    print("Make sure to supply the full path of the sample")
            