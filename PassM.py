import json
import os
import base64
import getpass
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from argon2.exceptions import (
    VerifyMismatchError,
)
from Cryptodome.Random import get_random_bytes
from argon2 import PasswordHasher

ph = PasswordHasher()

def Argon2Hash(string):
   

    hashed = ph.hash(string)
    parts = hashed.split('$')
    algorithm = parts[1]# boooo unimportant     
    version = parts[2]# boooo unimportant
    params = parts[3]#boooo unimportant
    salt_b64 = parts[4]#Salt 
    hash_b64 = parts[5]#Hash

    padding = '=' * (-len(hash_b64) % 4)
    raw_key_argon = base64.b64decode(hash_b64 + padding)
    return {
        "full_hash": hashed,
        "salt": salt_b64,
        "key": raw_key_argon.hex()  # or raw_key_argon if you want bytes
    }
    

def encrypt_aes(key, string):
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_text, tag = cipher.encrypt_and_digest(string.encode('utf-8'))

    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'nonce': b64encode(nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }
    
def decrypt_aes(tag,nonce,ciphertext, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        plain_text_bytes = cipher.decrypt_and_verify(ciphertext,tag)

        return plain_text_bytes.decode("utf-8")

    except ValueError:
        raise Exception("Decryption failed")

fileplace = "p.json"
masterplace = "master.json"


if not os.path.isfile(masterplace):
    master_password= getpass.getpass("Enter Master Password")
    confirm_mpass = getpass.getpass("Confirm Mpass (If you enter the wrong password it will restart the master password process)")
    if not master_password == confirm_mpass:
        print("Wrong Password")
        os.abort()
    else:
        print("Password Confirmed")
        saltnhashargon= Argon2Hash(master_password)
        

        print(saltnhashargon["key"])

        argonjsondata = {
            'argon': {
                "hash": saltnhashargon["full_hash"],
                "salt": saltnhashargon["salt"],
                "key": saltnhashargon["key"]
            }
        }

        
        with open(masterplace, "w") as masf:
            json.dump(argonjsondata, masf, indent=4, ensure_ascii=False)


else:
    master_password= getpass.getpass("Enter Master Password")
    with open(masterplace, 'r') as masf:
        jdata = json.load(masf)
        

    
    try:
        saltnhashargon =ph.verify(jdata['argon']['hash'], master_password)
        print(saltnhashargon)
    except VerifyMismatchError:
        print('Wrong Password')
        os.abort()

print("Welcome to the password manager")

keym=bytes.fromhex(jdata['argon']['key'])

while True:
    print("(Ctrl + C to exit)")
    qna = input('View your password (V) | Enter Password (P)')
    if qna == 'V' or qna == 'v':
        with open(fileplace, 'r') as fapf:
            fdata = json.load(fapf)
        if fdata:


            for id, entry in fdata.items():

                platform = decrypt_aes(
                    b64decode(entry["Platform"]["tag"]),
                    b64decode(entry["Platform"]["nonce"]),
                    b64decode(entry["Platform"]["cipher_text"]),
                    keym
                )

                
                username = decrypt_aes(
                    b64decode(entry["Username"]["tag"]),
                    b64decode(entry["Username"]["nonce"]),
                    b64decode(entry["Username"]["cipher_text"]),
                    keym
                )

                password = decrypt_aes(
                    b64decode(entry["Password"]["tag"]),
                    b64decode(entry["Password"]["nonce"]),
                    b64decode(entry["Password"]["cipher_text"]),
                    keym
                )

                print("--------------------")
                print("ID:", id)
                print("Platform:", platform)
                print("Username:", username)
                print("Password:", password)






            
        else:
            print("No Passwords Detected")
            continue
    elif qna == "P" or qna == 'p':
        print("------------------------------------")


    plat= input('Enter the Name of the Platform that you want to hide your credentials of d:')
    usern=input('Enter your Username/Email')
    userpass= getpass.getpass('Enter a Password')

    with open(masterplace, 'r') as masf:
            jdata = json.load(masf)
            
    Encrypted_pass = encrypt_aes(bytes.fromhex(jdata['argon']['key']), userpass)
    Encrypted_user = encrypt_aes(bytes.fromhex(jdata['argon']['key']), usern)
    Encrypted_plat = encrypt_aes(bytes.fromhex(jdata['argon']['key']), plat)

    print(Encrypted_pass)
    print(Encrypted_user)

    try:
        with open(fileplace, 'r', encoding='utf-8') as fapf:
            data = json.load(fapf)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}


    if data:
        new_id = str(max(map(int, data.keys())) + 1)
    else:
        new_id = "1"

    data[new_id] = {
        "Platform": Encrypted_plat,
        "Username": Encrypted_user,
        "Password": Encrypted_pass
    }

    with open(fileplace, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    
        
    












    
        
  

    

            
    
#Write the salt in the server and call it argon2salt
#Use the hash for aes-256 and then save that on the server



#with open(fileplace , "r") as file:
    #data = json.load(file)

#print(data["platform"])
#print(data["password"])



