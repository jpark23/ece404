import sys
from PrimeGenerator import PrimeGenerator
from BitVector import *
from rsa import getPrime

def generate():
    # 1. generate 3 different primes n1 and n2 and n3
    n1 = getPrime()
    while(1):
        n2 = getPrime()
        if (n2 != n1):
            break
    while(1):
        n3 = getPrime()
        if (n3 != n1 and n3 != n2):
            break
    print("Gottem")
    return [n1, n2, n3]

def encrypt(msgFile, _enc1, _enc2, _enc3, n123file):
    [n1, n2, n3] = generate()
    

def main():
    if(sys.argv[1] == '-e'):
        print("Encrypting...")
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif(sys.argv[1] == '-c'):
        print("Decrypting...")
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
main()
# py breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt #Steps 1 and 2
# py breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt #Step 3