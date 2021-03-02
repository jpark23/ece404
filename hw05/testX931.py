import x931
from BitVector import *

#Arguments:
# v0: 128-bit BitVector object containing the seed value
# dt: 128-bit BitVector object symbolizing the date and time
# key_file: String of file name containing the encryption key (in ASCII) for AES
# totalNum: integer indicating the total number of random numbers to generate
#Function Description
# Uses the arguments with the X9.31 algorithm to generate totalNum random
#   numbers as BitVector objects
#Returns a list of BitVector objects, with each BitVector object representing a
#   random number generated from X9.31
def x931(v0, dt, totalNum, key_file):
    # TODO - how does 256->128 bit AES change my algo.
    # 1. Date and time AES
    dt_aes_bv = AES(dt, key_file)
    # 2. XOR ^ with V0
    dt_aes_left_bv = dt_aes_bv ^ v0
    # 3. AES to Rj output
    dt_aesleft2_bv = AES(dt_aes_left_bv, key_file)
    # 4. take AESout step 1, XOR with AESout step 3
    dt_aesright_bv = dt_aes_bv ^ dt_aesleft2_bv
    # 5. AES above to V(j+1) out
    dt_Vj1 = AES(dt_aesright_bv, key_file)

if __name__ == "__main__":
    v0 = BitVector(textstring="computersecurity") #v0 will be  128 bits
    #As mentioned before, for testing purposes dt is set to a predetermined value
    dt = BitVector(intVal = 501, size=128)
    listX931 = x931.x931(v0,dt,3,"keyX931.txt")
    #Check if list is correct
    print("{}\n{}\n{}".format(int(listX931[0]),int(listX931[1]),int(listX931[2])))