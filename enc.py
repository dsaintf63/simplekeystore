# Password phrase
# Author: Tim Strunk
# Date: 13 December 2020 The year of the mask -[ ]- 
# Description: This is a simple encryption decryption application where you can save small one prases in a file archiver encrypted. Each line is referenced by a clear tag. 
#   No need to decrypt the whole file just to get one tag. So you can display and decrypt only what you need.
#   The lines are a separate password so they do not need to match the password to the file.

import argparse
import hashlib
import base64
import os
import getpass
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def clear(): 
  
    # for windows 
    if os.name == 'nt': 
        _ = os.system('cls') 
  
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = os.system('clear') 
                
def encrypt(key, source, encode=True):
    key = hashlib.sha256(key).digest() # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.strip().encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    
    return data[:-padding]  # remove the padding

if __name__ == "__main__":
    fileHandle = None
    clearTextFile = False
    secret = None
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file",dest='file', required=True, help="File to read and write")
    
    args = ap.parse_args()
    
    try: 
        secret = getpass.getpass('\t File Password: ').strip()
            
        if len(secret) < 1 :
            clearTextFile = True
            
            secret = getpass.getpass('\t Content Password: ').strip()
            
        if clearTextFile or not os.path.isfile( args.file ) :
            p2 = getpass.getpass('\t Verify       : ').strip()
            
            if secret != p2 :
                del secret
                secret = None
                exit()
                
            del p2
        
        secret = hashlib.sha256(secret.encode('utf-8')).hexdigest().encode('utf-8')
            
    except Exception as error: 
        print('ERROR', error)       
        exit()
    
    Lines = None
    if os.path.isfile( args.file ) :
        encFile = None 
        fileHandle = None
        
        # Open the file
        if clearTextFile :
            fileHandle = open(args.file, "r")
            Lines = fileHandle.readlines()
        else :
            fileHandle = open(args.file, "r")
            encFile = fileHandle.read() 
        fileHandle.close()
        
        if Lines is None and encFile is not None and len(encFile.strip() ) > 0 :
            attemptCount = 3
            while Lines is None and attemptCount > 0 :
                try :
                    Lines = decrypt(secret, encFile ).decode('utf-8')
                    Lines = Lines.split("\n")
                except Exception as error:
                    Lines = None
                    print('ERROR', error) 
                    print( " Error: the password is not correct" )
                    secret = getpass.getpass('\tPassword: ').strip()
                    secret = hashlib.sha256(secret.encode('utf-8')).hexdigest().encode('utf-8')
                    
                attemptCount -= 1
        elif Lines is None :
            Lines = []
    else :
        Lines = []
    
    if Lines is not None :
        answer = None
        
        print("Using Archive file: " + args.file )
        print("---------------------------------")
        
        while secret is not None and answer != 'e'  :
            print("\n\tChoose: ")
            print("\t\t l   : List all Vars")
            print("\t\t a   : Add or edit a value in the list. To add, no")
            print("\t\t x n : Display Decrypted value record n")
            print("\t\t d n : Delete a record n")
            print("\t\t e   : Exit")
            answer = input("\n\tSelect: ")
            
            if answer == 'l' :
                print("\n\tList Of Vars")
                i=0
                
                for line in Lines :
                    if len(line.strip()) > 0: 
                        var, val = line.split(":",1)
                        var = var.strip()
                        print("\t\t" + str(i) + ". " + str(var))
                    i += 1
            elif answer == 'a' :
                var = input("\n\t\t Enter Name : ")
                val = input("\t\t Enter Secret : ")
                
                var = var.strip() 
                val = val.strip()
                val = encrypt(secret, val.encode('utf-8'))

                # Find Record
                record = None
                i=0
                for line in Lines :
                    if len( line.strip() ) > 0 :
                        var2, val2 = line.split(":",1)
                        var2 = var2.strip()
                        if var2 == var :
                            record = i
                    i += 1
                
                if record is None :
                    Lines.append(var + " : " + val + "\n" )
                else :
                    Lines[record] = var + " : " + val + "\n"
                
                # Encrypt the array
                clearFile = ""
                for eaLine in Lines:
                    if len(eaLine.strip()) > 0:
                        clearFile = clearFile.strip()
                        clearFile += "\n" + eaLine
                clearFile = clearFile.strip()
                clearFile = encrypt(secret, clearFile.encode('utf-8'))                
                # Write The file
                fileHandle = open(args.file, 'w') 
                fileHandle.write(clearFile) 
                fileHandle.close()
                
                del val
            elif answer[:1] == 'x' :        
                record = None
                var = None
                val = None
                    
                try :
                    var, val = answer.split(" ",1)
                except Exception as error:
                    var = None
                    val = None
                    print("\n\t Error: Forgot to ref record number to display record")
                    
                if var is not None :
                    try :
                        i = int(val.strip())
                        record = i
                    except Exception as error:
                        pass
                    
                    if record is not None and record < len(Lines) :
                        var = None
                        val = None
                         
                        try :
                            var, val = Lines[record].split(":",1)
                        except Exception as error:
                            var = None
                            val = None
                            print("\n\t Error: Record number " + str( record) + " is bad")
                            
                        if var is not None :
                            var = var.strip() 
                            val = val.strip()
                            
                            try :
                                val = decrypt(secret, val )
                            except Exception as error:
                                val = " Error: the password is not correct for this value"
                                
                            print("\t\t "+ str(var) + " = " + str(val))
            
            elif answer[:1] == 'd' :  
                record = None
                var = None
                val = None
                    
                try :
                    var, val = answer.split(" ",1)
                except Exception as error:
                    var = None
                    val = None
                    print("\n\t Error: Forgot to ref record number to delete record")
                
                if var is not None :
                    try :
                        i = int(val.strip())
                        record = i
                    except Exception as error:
                        pass
                    
                    if record is not None and record < len(Lines) :
                        del Lines[i]
                    
                        # Encrypt the array
                        clearFile = ""
                        for eaLine in Lines:
                            if len(eaLine.strip()) > 0:
                                clearFile = clearFile.strip()
                                clearFile += "\n" + eaLine
                        clearFile = clearFile.strip()
                        clearFile = encrypt(secret, clearFile.encode('utf-8'))                
                        # Write The file
                        fileHandle = open(args.file, 'w') 
                        fileHandle.write(clearFile) 
                        fileHandle.close()
                   
    clear()