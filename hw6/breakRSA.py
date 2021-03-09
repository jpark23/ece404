import sys
from PrimeGenerator import PrimeGenerator
from BitVector import *
e = 3

def testPrime(prime):
    prime_bv = BitVector(intVal=prime, size=128)
    leftmost = prime_bv.length()
    if (prime_bv[leftmost] == 0 or prime_bv[leftmost-1] == 0):
        return 0
    test_gcd = gcd(prime-1, e)
    if (test_gcd != 1):
        return 0
    return prime

def getPrime():
    while(1):
        generator = PrimeGenerator(bits=128)
        num = generator.findPrime()
        num = testPrime(num)
        if (num):
            break  
    return num

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

def encrypt3(msgFile, _enc1, _enc2, _enc3, n123file):
    [n1, n2, n3] = generate()
    FILE1 = open(_enc1, 'w')
    FILE2 = open(_enc2, 'w')
    FILE3 = open(_enc3, 'w')
    ## (plain)^e mod n = cipher ##
    file_bv = BitVector(filename=msgFile)
    while(file_bv.more_to_read):
        ptext_bv = file_bv.read_bits_from_file(128)
        ptext_bv.pad_from_right(128-ptext_bv.length())
        ptext_bv.pad_from_left(128)
        c1 = pow(ptext_bv, e, n1)
        c2 = pow(ptext_bv, e, n2)
        c3 = pow(ptext_bv, e, n3)
        c1_bv = BitVector(intVal=c1, size=256)
        c2_bv = BitVector(intVal=c2, size=256)
        c3_bv = BitVector(intVal=c3, size=256)
        FILE1.write(c1_bv.get_bitvector_in_hex())
        FILE2.write(c2_bv.get_bitvector_in_hex())
        FILE3.write(c3_bv.get_bitvector_in_hex())
    FILE1.close()
    FILE2.close()
    FILE3.close()

def main():
    if(sys.argv[1] == '-e'):
        print("Encrypting...")
        encrypt3(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif(sys.argv[1] == '-c'):
        print("Decrypting...")
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
main()
# py breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt #Steps 1 and 2
# py breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt #Step 3