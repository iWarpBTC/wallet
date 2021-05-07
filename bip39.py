from random import getrandbits
from hashlib import pbkdf2_hmac
from hashlib import sha256
from binascii import unhexlify
from crypto import S256Bod, N, G

def generuj_seed(bity):   
    # pseudonahodne cislo; pro nase ucely postacuje
    entropy = getrandbits(bity)
    print('Vygenerována entropie: {}'.format(hex(entropy)))
    # prevedeme na hexa retezec
    hex_str_entropy = unhexlify(hex(entropy)[2:].zfill(32))
    # zahashujeme 
    check = sha256(hex_str_entropy).hexdigest()
    print('Checksum hash entropie: {}'.format(check))
    # pripojime 4 bity na konec entropie
    b = bin(entropy)[2:].zfill(bity) + bin(int(check, 16))[2:].zfill(256)[:(4 if bity == 128 else 8)]
    print('Binární reprezentace: \n{} + {}'.format(bin(entropy)[2:].zfill(bity), bin(int(check, 16))[2:].zfill(256)[:(4 if bity == 128 else 8)]))

    with open("english.txt", "r", encoding="utf-8") as f:
        wordlist = [w.strip() for w in f.readlines()]

    slova_list = []
    # prevedeme na slova
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        slova_list.append(wordlist[idx])
        slova = " ".join(slova_list)

    print() 
    print (slova)
    print()

    passphrase = input('Zadej passphase (nebo ponech prázdné): ')
    # rozsirime slova na seed, ten rovnou vratime
    return pbkdf2_hmac("sha512", slova.encode("utf-8"), ('mnemonic'+passphrase).encode("utf-8"), 2048)
    

def parsuj_seed(vstup):
    if vstup:
        slova = vstup.split(' ')
    else:
        slova = []

    if len(slova) != 12 and len(slova) != 24:
        print('Zadáno {} slov, avšak očekáváno 12 nebo 24.'.format(len(slova)))
        return b''

    with open("english.txt", "r", encoding="utf-8") as f:
        wordlist = [w.strip() for w in f.readlines()]

    b = ''
    for i in range(len(slova)):
        if slova[i] in wordlist:
            b += bin(wordlist.index(slova[i]))[2:].zfill(11)
        else:
            print('Neznámé slovo {}.'.format(slova[i]))
            return b''

    hex_ent = unhexlify(hex(int(b[:(128 if len(slova) == 12 else 256)], 2))[2:].zfill(32))  
    check = sha256(hex_ent).hexdigest()
    print('checksum hash: {}'.format(check))
    checksum = int(check[:(1 if len(slova) == 12 else 2)], 16)
    check_res = int(b[(128 if len(slova) == 12 else 256):], 2) == checksum
    print('checksum {}'.format(check_res))
    if not check_res:
        return b''

    passphrase = input('Zadej passphase (nebo ponech prázdné): ')
    # rozsirime slova na seed, ten rovnou vratime
    return pbkdf2_hmac("sha512", vstup.encode("utf-8"), ('mnemonic'+passphrase).encode("utf-8"), 2048)

def tvrzeny_priv(priv, chain, index=0):
    data = b'\x00' + priv + (pow(2, 31) + index).to_bytes(4, 'big') 
    newkey = hmac.new(chain, data, digestmod=hashlib.sha512).digest()
    child_priv = (int.from_bytes(newkey[:32], 'big') + int.from_bytes(priv, 'big')) % N
    return child_priv.to_bytes(32, 'big') + newkey[32:]

def netvrzeny_priv(priv, pub, chain, index=0):
    data = pub + index.to_bytes(4, 'big')
    newkey = hmac.new(chain, data, digestmod=hashlib.sha512).digest()
    child_priv = (int.from_bytes(newkey[:32], 'big') + int.from_bytes(priv, 'big')) % N
    return child_priv.to_bytes(32, 'big') + newkey[32:]

def odvozeni_pub(pub, chain, index=0):
    data = pub + index.to_bytes(4, 'big')
    newkey = hmac.new(chain, data, digestmod=hashlib.sha512).digest()
    child_pub = S256Bod.parse(pub) + int.from_bytes(newkey[:32], 'big') * G
    return child_pub.sec() + newkey[32:]

def netrv_priv_rev(ch_priv, p_xpub, index=0):
    data = p_xpub[:33] + index.to_bytes(4, 'big')
    newkey = hmac.new(p_xpub[33:], data, digestmod=hashlib.sha512).digest()
    parent_priv = (int.from_bytes(ch_priv, 'big') - int.from_bytes(newkey[:32], 'big')) % N
    return parent_priv