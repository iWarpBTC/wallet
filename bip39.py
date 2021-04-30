from random import getrandbits
import hashlib 
import hmac
from binascii import unhexlify
from crypto import S256Bod, encode_base58, G, N, tvrzeny_priv, netvrzeny_priv, hash160

print()
print('iWarpova VZDELAVACI wallet; NEPOUZIVEJTE K JINYM UCELUM!')
print()

# nacteni wordlistu do listu
with open("english.txt", "r", encoding="utf-8") as f:
    wordlist = [w.strip() for w in f.readlines()]

# pseudonahodne cislo
entropy = getrandbits(128)

print('pocatecni entropie (dekadicky): {}'.format(entropy))

# prevedeme na hexa retezec
hex_str_entropy = unhexlify(hex(entropy)[2:].zfill(32))

# zahashujeme 
check = hashlib.sha256(hex_str_entropy).hexdigest()
print('checksum hash entropie: {}'.format(check))

# pripojime 4 bity na konec entropie
b = bin(entropy)[2:].zfill(128) + bin(int(check, 16))[2:].zfill(256)[:4]

print('{} + {}'.format(bin(entropy)[2:].zfill(128), bin(int(check, 16))[2:].zfill(256)[:4]))

# prevedeme na slova
result = []
for i in range(len(b) // 11):
    idx = int(b[i * 11 : (i + 1) * 11], 2)
    result.append(wordlist[idx])
    result_phrase = " ".join(result)

print() 
print (result_phrase)
print()

passphrase = ''#input('zadej passphrase: ')

# rozsirime slova na seed
seed = hashlib.pbkdf2_hmac("sha512", result_phrase.encode("utf-8"), ('mnemonic'+passphrase).encode("utf-8"), 2048)
print('seed: {}'.format(seed.hex()))

# vygenerujeme master xpriv
master_xpriv = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()
print('master xpriv v raw: {}'.format(master_xpriv.hex()))

print()

# zkusime se ponekud humpolackym zpusobem podivat na dvacet adres ze standardni cesty m/44'/0'/0'/0/x
m44h = tvrzeny_priv(master_xpriv[:32], master_xpriv[32:], 44)
m44h0h = tvrzeny_priv(m44h[:32], m44h[32:])
m44h0h0h = tvrzeny_priv(m44h0h[:32], m44h0h[32:])
m44h0h0hpub = (int.from_bytes(m44h0h0h[:32], 'big') * G).sec()
m44h0h0h0 = netvrzeny_priv(m44h0h0h[:32], m44h0h0hpub, m44h0h0h[32:])
m44h0h0h0pub = (int.from_bytes(m44h0h0h0[:32], 'big') * G).sec()

for i in range (20):
    m44h0h0h0i = netvrzeny_priv(m44h0h0h0[:32], m44h0h0h0pub, m44h0h0h0[32:], i)
    child_pub = int.from_bytes(m44h0h0h0i[:32], 'big') * G
    print('m/44h/0h/0h/0/{}: {}'.format(i, child_pub.address()))

print()

# a rovnou i na deset change
m44h0h0h1 = netvrzeny_priv(m44h0h0h[:32], m44h0h0hpub, m44h0h0h[32:], 1)
m44h0h0h1pub = (int.from_bytes(m44h0h0h1[:32], 'big') * G).sec()

for i in range (10):
    m44h0h0h1i = netvrzeny_priv(m44h0h0h1[:32], m44h0h0h1pub, m44h0h0h1[32:], i)
    child_pub = int.from_bytes(m44h0h0h1i[:32], 'big') * G
    print('m/44h/0h/0h/1/{}: {}'.format(i, child_pub.address()))

print()

# zkusime sestavit radny xpub
version = b'\x04\x88\xb2\x1e'
depth = (3).to_bytes(1, 'big')
finger = hash160( (int.from_bytes(m44h0h[:32], 'big') * G).sec() )[:4]
childnum = pow(2, 31).to_bytes(4, 'big')
ser = version + depth + finger + childnum + m44h0h0h[32:] + m44h0h0hpub
print('master xpub v base58check: {}'.format(encode_base58(ser + hashlib.sha256(hashlib.sha256(ser).digest()).digest()[:4] )))

