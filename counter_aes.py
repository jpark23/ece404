#Arguments:
# iv: 128-bit initialization vector
# image_file: input .ppm image file name
# out_file: encrypted .ppm image file name
# key_file: String of file name containing encryption key (in ASCII)
#Function Descrption:
# Encrypts image_file using CTR mode AES and writes said file to out_file. No
    #required return value.
def ctr_aes_image(iv,image_file='image.ppm',out_file='enc_image.ppm', key_file='key.txt'):
    print("Not attempted yet. :(")

from AES_image import ctr_aes_image
from BitVector import *
iv = BitVector(textstring='computersecurity') #iv will be 128 bits
ctr_aes_image(iv,'image.ppm','enc_image.ppm','keyCTR.txt')