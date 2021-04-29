from random import getrandbits
import hashlib 
import hmac
from binascii import unhexlify

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

passphrase = input('zadej passphrase: ')

seed = hashlib.pbkdf2_hmac("sha512", result_phrase.encode("utf-8"), ('mnemonic'+passphrase).encode("utf-8"), 2048)
print('seed: {}'.format(seed.hex()))

master = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()
print('master priv: {}'.format(master.hex()))