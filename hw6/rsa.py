import sys
from PrimeGenerator import PrimeGenerator
from BitVector import *

e = 65537 # defined from assignment doc
e_bv = BitVector(intVal=65537)

# py rsa.py -g p.txt q.txt
# py rsa.py -e message.txt p.txt q.txt encrypted.txt
# py rsa.py -d encrypted.txt p.txt q.txt decrypted.txt

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
    if (prime_bv[0] == 0 or prime_bv[1] == 0):
        return 0
    test_gcd = gcd(prime-1, e)
    if (test_gcd != 1):
        return 0
    return prime

def generate(p_out, q_out):
    # 1. generate two different primes p and q
    p = getPrime()
    while(1):
        q = getPrime()
        if (q != p):
            break
    
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
    
    print("Gottem")

def main():
    if sys.argv[1] == '-g':
        print("Generating...")
        generate(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-e':
        print("Encrypting...")
    elif sys.argv[1] == '-d':
        print("Decrypting...")
    else:
        print("Something went wrong...")
        exit(1)

main()