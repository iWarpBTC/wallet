from random import getrandbits
import hashlib 
import hmac
from binascii import unhexlify
from crypto import S256Bod, encode_base58, G, N, tvrzeny_priv

# nacteni wordlistu do listu
with open("english.txt", "r", encoding="utf-8") as f:
    wordlist = [w.strip() for w in f.readlines()]

# pseudonahodne cislo
entropy = getrandbits(128)
entropy = 248012469217656750259608001750896537336 #testovaci

print('pocatecni entropie (dekadicky): {}'.format(entropy))

# prevedeme na hexa retezec
hex_str_entropy = unhexlify(hex(entropy)[2:].zfill(32))

# zahashujeme 
check = hashlib.sha256(hex_str_entropy).hexdigest()
print('checksum hash entropie: {}'.format(check))

print(bin(entropy)[2:])
print(bin(int(check, 16))[2:].zfill(256)[:4])

# pripojime 4 bity na konec entropie
b = bin(entropy)[2:].zfill(128) + bin(int(check, 16))[2:].zfill(256)[:4]

print(b)

# prevedeme na slova
result = []
for i in range(len(b) // 11):
    idx = int(b[i * 11 : (i + 1) * 11], 2)
    result.append(wordlist[idx])
    result_phrase = " ".join(result)
    
print (result_phrase)

passphrase = ''#input('zadej passphrase: ')

seed = hashlib.pbkdf2_hmac("sha512", result_phrase.encode("utf-8"), ('mnemonic'+passphrase).encode("utf-8"), 2048)
print('seed: {}'.format(seed.hex()))

master_xpriv = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()
print('master xpriv: {}'.format(master_xpriv.hex()))

public = int.from_bytes(master_xpriv[:32], "big") * G
print('master pub: {}'.format(public))

version = b'\x04\x88\xb2\x1e'
depth = b'\x00'
finger = b'\x00\x00\x00\x00'
chain = master_xpriv[32:]

ser = version+depth+finger+finger+chain+public.sec(True)
print(encode_base58(ser + hashlib.sha256(hashlib.sha256(ser).digest()).digest()[:4] ))


m44h = tvrzeny_priv(master_xpriv[:32], chain, 44)

m44h0h = tvrzeny_priv(m44h[:32], m44h[32:])

m440h0h = tvrzeny_priv(m44h0h[:32], m44h0h[32:])

child_pub = int.from_bytes(m440h0h[:32], 'big') * G
print(child_pub.address())
