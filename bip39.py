from hashlib import sha256
from binascii import unhexlify


hexa = hex( int('01010011010001111111100111001101110100001001000100111011010101001011000111010100111000101100111100010100001100100000000110110111', 2 ))


print (hexa)

stre = unhexlify(hexa[2:])

hasher = sha256()
hasher.update(stre)
print( hasher.hexdigest() )
