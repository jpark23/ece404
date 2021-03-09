import sys
from PrimeGenerator import PrimeGenerator
from BitVector import *

e = 65537 # defined from assignment doc
e_bv = BitVector(intVal=65537)

def gcd(x, y):
    if (x == 0):
        return y
    return gcd(y % x, x)

def getPrime():
    while(1):
        generator = PrimeGenerator(bits=128)
        num = generator.findPrime()
        num = testPrime(num)
        if (num):
            break  
    return num

def testPrime(prime):
    prime_bv = BitVector(intVal=prime)
    leftmost = prime_bv.length()
    if (prime_bv[leftmost] == 0 or prime_bv[leftmost-1] == 0):
        return 0
    test_gcd = gcd(prime-1, e)
    if (test_gcd != 1):
        return 0
    return prime

def keygen(p, q, flag):
    # 2. calculate the modulus n = p * q 
    n = p * q

    # 3. Calculate the totient phi(n) = (p-1)*(q-1)
    phi_n = (p-1) * (q-1)

    # 4. Use e = 65537
    # declared globally

    # 5. Calculate for the private exponent a value for d such that
    #     d = e^-1 mod phi(n)
    phi_bv = BitVector(intVal=phi_n)
    #e_inv = e ** -1 TODO - sort this out, need to use int, for line 56
    e_inv_bv = BitVector(intVal=e)
    d_bv = e_inv_bv.multiplicative_inverse(phi_bv)
    d = d_bv.int_val()

    # 6. Public Key = [e, n]
    public = [e, n]

    # 7. Private Key = [d, n]
    private = [d, n]

    if (flag == 'all'):
        return [e, d, n]
    elif (flag == 'public'):
        return public
    elif (flag == 'private'):
        return private

def generate(p_out, q_out):
    # 1. generate two different primes p and q
    p = getPrime()
    while(1):
        q = getPrime()
        if (q != p):
            break
    
    [e, d, n] = keygen(p, q)
    
    FILEOUTP = open(p_out, "w")
    FILEOUTQ = open(q_out, "w")
    FILEOUTP.write(str(p))
    FILEOUTQ.write(str(q))
    FILEOUTP.close()
    FILEOUTQ.close()
    print("Gottem")

def encrypt(messageFile, pFile, qFile, outFile):
    ## (plain)^e mod n = cipher ##
    FILEOUT = open(outFile, 'w')
    FILEINp = open(pFile, 'r')
    FILEINq = open(qFile, 'r')
    p = int(FILEINp.read())
    q = int(FILEINq.read())
    [e, n] = keygen(p, q, 'public')
    file_bv = BitVector(filename=messageFile)
    while(file_bv.more_to_read):
        ptext_bv = file_bv.read_bits_from_file(128)
        ptext_bv.pad_from_right(128 - ptext_bv.length())
        ptext_bv.pad_from_left(128)
        ctext = pow(ptext_bv.int_val(), e, n)
        ctext_bv = BitVector(intVal=ctext, size=256)
        ctext_bv.pad_from_right(256 - ctext_bv.length())
        FILEOUT.write(ctext_bv.get_bitvector_in_hex())
    FILEOUT.close()
    print("Done!")

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

def crt(ctext_bv, d, p, q, n):
    Vp = pow(ctext_bv.int_val(), d, p)
    Vq = pow(ctext_bv.int_val(), d, q)
    Xp = q * (MI(q, p))
    Xq = p * (MI(p, q))
    ptext = ((Vp * Xp) + (Vq * Xq)) % n
    return BitVector(intVal=ptext, size=256)

def decrypt(encFile, pFile, qFile, outFile):
    PFILE = open(pFile, 'r')
    QFILE = open(qFile, 'r')
    FILEOUT = open(outFile, 'w')
    p = int(PFILE.read())
    q = int(QFILE.read())
    [d, n] = keygen(p, q, 'private')
    FILEIN = open(encFile, 'r')
    while(1):
        read = FILEIN.read(64)
        ctext_bv = BitVector(hexstring=read)
        if (ctext_bv.length() <= 0):
            break
        ptext_padded = crt(ctext_bv, d, p, q, n)
        [dontuse, ptext_bv] = ptext_padded.divide_into_two()
        FILEOUT.write(ptext_bv.get_bitvector_in_ascii())
    print("Done!")

def main():
    if sys.argv[1] == '-g':
        print("Generating...")
        generate(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-e':
        print("Encrypting...")
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif sys.argv[1] == '-d':
        print("Decrypting...")
        decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        print("Something went wrong...")
        exit(1)

# py rsa.py -g p1.txt q1.txt
# py rsa.py -e message.txt p.txt q.txt encrypted.txt
# py rsa.py -d testfiles/test_encrypted.txt p.txt q.txt decrypted.txt
main()