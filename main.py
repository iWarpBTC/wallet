import bip39

menu1_options = {
    1: 'Vygenerovat seed 128b',
    2: 'Vygenerovat seed 256b',
    3: 'Vlastní seed',
    4: 'Konec',
}

menu2_options = {
    1: 'Tvrzený potomek',
    2: 'Potomek',
    3: 'Zpět',
    4: 'Konec',
}

def print_menu(index):
    if index == 1:
        menu_options = menu1_options
    else:
        menu_options = menu2_options

    for key in menu_options.keys():
        print (key, '--', menu_options[key] )

    
print()
print('iWarpova VZDĚLÁVACÍ wallet; NEPOUŽÍVEJTE K JINÝM ÚČELŮM!')
print()

# nacteni wordlistu do listu
with open("english.txt", "r", encoding="utf-8") as f:
    wordlist = [w.strip() for w in f.readlines()]

seed = b''

while(seed==b''):
    print_menu(1)
    option = ''
    try:
        option = int(input('Vyber: '))
    except:
        print('Neplatný výběr. Zadej číslo ...')
    if option == 1:
        seed = bip39.generuj_seed(128)
    elif option == 2:
        seed = bip39.generuj_seed(256)
    elif option == 3:
        while(seed==b''):
            slova = input('Zadej slova seedu (12/24, bez passphrase): ') 
            if slova == '':
                break 
            else:
                seed = bip39.parsuj_seed(slova)
    elif option == 4:
        print('Končím.')
        exit()
    else:
        print('Neplatný výběr. Zadej číslo mezi 1 a 4.')

print('seed: {}'.format(seed.hex()))

while(1):
    print('Cesta: m/')
    
    print_menu(2)
    option = ''
    try:
        option = int(input('Vyber: '))
    except:
        print('Neplatný výběr. Zadej číslo ...')
    if option == 1:
        print('a')
    elif option == 2:
        print('b')
    elif option == 3:
        print('c')
    elif option == 4:
        print('Končím.')
        exit()
    else:
        print('Neplatný výběr. Zadej číslo mezi 1 a 4.')
