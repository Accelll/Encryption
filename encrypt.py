import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def encrypt(key, filename):     
	chunksize = 64*1024                                         #how many chunks to read from file
	outputFile = "(encrypted)"+filename                         #New fiilename
	filesize = str(os.path.getsize(filename)).zfill(16)         #calculates filesize
	IV = Random.new().read(16)                                  #creates an initial vector for random ciphertext

	encryptor = AES.new(key, AES.MODE_CBC, IV)                  #choses AES chain block cipher mode

	with open(filename, 'rb') as infile:                        #opens file as binary
		with open(outputFile, 'wb') as outfile:                 #creates the outputfile as write binary
			outfile.write(filesize.encode('utf-8'))             #determines file size
			outfile.write(IV)                                   

			while True:                                         
				chunk = infile.read(chunksize)                  #reads file chunk size

				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += b' ' * (16 - (len(chunk) % 16))    #if chunk is not equal to mod 16 pad the chunk to 16

				outfile.write(encryptor.encrypt(chunk))         #writes encrypted file


def decrypt(key, filename):                                     
	chunksize = 64*1024                                         #how many chunks to read from file
	outputFile = filename[11:]                                  #reads the IV

	with open(filename, 'rb') as infile:                        #opens file as binary
		filesize = int(infile.read(16))                         #reads file in chunks
		IV = infile.read(16)                                    #removes the IV from the file

		decryptor = AES.new(key, AES.MODE_CBC, IV)              #sets up AES chain block

		with open(outputFile, 'wb') as outfile:                 #opens output file
			while True:
				chunk = infile.read(chunksize)                  #while chunk is equal to infile chunk size

				if len(chunk) == 0:                             
					break

				outfile.write(decryptor.decrypt(chunk))         #outputs the decrypted file
			outfile.truncate(filesize)                          #once out of data truncate file to original size (removes padding)


def getKey(password):                                           #pulls the password
	hasher = SHA256.new(password.encode('utf-8'))               #hash inputted password to utf-8
	return hasher.digest()                                      

def Main():
	choice = input("Would you like to (E)ncrypt or (D)ecrypt?: ")   #asks for encrypt or decrypt

	if choice == 'E':
		filename = input("File to encrypt: ")                       #chooses filename
		password = input("Password: ")                              #creates password
		encrypt(getKey(password), filename)                         #runs the encryption function
		print("Done.")
	elif choice == 'D':
		filename = input("File to decrypt: ")                       #chooses filename
		password = input("Password: ")                              #creates password
		decrypt(getKey(password), filename)                         #runs the encryption function
		print("Done.")
	else:
		print("No Option selected, closing...")

if __name__ == '__main__':
	Main()                                                          #calls the main function
