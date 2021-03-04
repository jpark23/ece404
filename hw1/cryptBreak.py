import sys
from BitVector import *

#Arguments:
#   ciphertextFile: String containing file name of the ciphertext (e.g. encrypted.txt)
#   key_bv: 16-bit BitVector of the key used to try to decrypt the ciphertext
# Function Description:
#   Attempts to decrypt ciphetext contained in ciphertextFile using key_bv and returns
#       the original plaintext as a string
#   This function will decrypt the message for a single key
#   Basically I have this key, and I have an encrypted message, give me the og message

def cryptBreak(ciphertextFile, key_bv):
    # code below adapted from DecryptForFun.py
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    # Reduce passphrase to a bit array of size BLOCKSIZE
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes : (i + 1) * numbytes]
        bv_iv ^= BitVector(textstring = textstr)
    
    # Create a bitvector from the ciphertext hex string
    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring = FILEIN.read())

    # Reduce the key to a bit array of size BLOCKSIZE
    # not necessary

    # Create a bitvector to store the decrypted plaintext bit array
    decrypted_msg_bv = BitVector(size = 0)

    # Differential XORing of bit blocks and decryption
    previous_decrypted_bv = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_bv
        previous_decrypted_bv = temp
        bv ^= key_bv
        decrypted_msg_bv += bv

    # Extract plaintext from the decrypted bitvector
    output = decrypted_msg_bv.get_text_from_bitvector()
    return output

# for someRandomInteger in range(65537):
#     key_bv = BitVector(intVal = someRandomInteger, size = 16)
#     decryptedMessage = cryptBreak("encrypted.txt", key_bv)
#     if 'Yogi Berra' == decryptedMessage:
#         print('Encryption Broken!')
#         break

key_bv = BitVector(intVal = 30053, size = 16)
decryptedMessage = cryptBreak("encrypted.txt", key_bv)
if 'Yogi Berra' in decryptedMessage:
    print('Encryption Broken!')