import sys
from PrimeGenerator import PrimeGenerator
from BitVector import *
from solve_pRoot_BST import solve_pRoot
e = 3

# the function below is taken from lecture notes
def MI(num, mod):
    '''
    This function uses ordinary integer arithmetic implementation of the
    Extended Euclid's Algorithm to find the MI of the first-arg integer
    vis-a-vis the second-arg integer.
    '''
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
    MI = (x_old + MOD) % MOD
    return MI

def gcd(x, y):
    if (x == 0):
        return y
    return gcd(y % x, x)

def testPrime(prime):
    prime_bv = BitVector(intVal=prime)
    firstBit = prime_bv[2:][0]
    secondBit = prime_bv[2:][1]
    if (firstBit == 0 or secondBit == 0):
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
    return [n1, n2, n3]

def write3(n123file, n1, n2, n3):
    FILEOUT = open(n123file, 'w')
    FILEOUT.write(str(n1))
    FILEOUT.write('\n')
    FILEOUT.write(str(n2))
    FILEOUT.write('\n')
    FILEOUT.write(str(n3))
    FILEOUT.write('\n')
    FILEOUT.close()

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
        c1 = pow(ptext_bv.int_val(), e, n1)
        c2 = pow(ptext_bv.int_val(), e, n2)
        c3 = pow(ptext_bv.int_val(), e, n3)
        c1_bv = BitVector(intVal=c1, size=256)
        c2_bv = BitVector(intVal=c2, size=256)
        c3_bv = BitVector(intVal=c3, size=256)
        FILE1.write(c1_bv.get_bitvector_in_hex())
        FILE2.write(c2_bv.get_bitvector_in_hex())
        FILE3.write(c3_bv.get_bitvector_in_hex())
    FILE1.close()
    FILE2.close()
    FILE3.close()
    write3(n123file, n1, n2, n3)

def decrypt3(enc1File, enc2File, enc3File, n123File, crackedFile):
    # get key info
    FILEIN = open(n123File, 'r')
    n1 = int(FILEIN.readline())
    n2 = int(FILEIN.readline())
    n3 = int(FILEIN.readline())
    N = n1 * n2 * n3
    N1 = N // n1
    N2 = N // n2
    N3 = N // n3
    n1_inv = MI(N1, n1)
    n2_inv = MI(N2, n2)
    n3_inv = MI(N3, n3)
    FILE1 = open(enc1File, 'r')
    FILE2 = open(enc2File, 'r')
    FILE3 = open(enc3File, 'r')
    FILEOUT = open(crackedFile, 'w')
    while(1):
        read1 = FILE1.read(64)
        read2 = FILE2.read(64)
        read3 = FILE3.read(64)
        ctxt1_bv = BitVector(hexstring=read1)
        if (ctxt1_bv.length() <= 0):
            break
        ctxt2_bv = BitVector(hexstring=read2)
        ctxt3_bv = BitVector(hexstring=read3)
        bigSum = (ctxt1_bv.int_val()*N1*n1_inv)+(ctxt2_bv.int_val()*N2*n2_inv)+(ctxt3_bv.int_val()*N3*n3_inv)
        m3 = bigSum % N
        m = solve_pRoot(3, m3)
        _m_bv = BitVector(intVal=m, size=256)
        [dontuse, m_bv] = _m_bv.divide_into_two()
        FILEOUT.write(m_bv.get_bitvector_in_ascii())
def main():
    if(sys.argv[1] == '-e'):
        print("Encrypting...")
        encrypt3(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        print("Done")
    elif(sys.argv[1] == '-c'):
        print("Cracking...")
        decrypt3(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        print("Done")
main()
# py breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt #Steps 1 and 2
# py breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt #Step 3