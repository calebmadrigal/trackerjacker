import re
from urllib.request import urlopen

IEEE_OUI_URL = 'https://standards-oui.ieee.org/oui/oui.txt'

def get_oui():
    data = urlopen(IEEE_OUI_URL).readlines()
    oui = ''
    for line in data:
        line = line.decode()
        if "(base 16)" not in line:
            continue
        # This line taken from https://gist.github.com/Sets88/8194159
        ven = tuple(re.sub("\s*([0-9a-zA-Z]+)[\s\t]*\(base 16\)[\s\t]*(.*)\n", r"\1;;\2", line).split(";;"))
        oui_line = '='.join(ven).strip() + '\n'
        oui += oui_line
    with open('oui.txt', 'w') as f:
        f.write(oui)
    print('Wrote oui.txt')
    return oui

if __name__ == '__main__':
    get_oui()
