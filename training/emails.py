import random

TLDS = ['com', 'org', 'net', 'edu', 'io']
SEPARATORS = ['', '.', '-', '_']

def permutate_email(firstname, lastname, organization, case=None, separator=None):
    
    tld = random.choice(TLDS)
    if case == None:
        case = random.randint(0, 9)
    if separator == None:
        separator = random.choice(SEPARATORS)

    if case == 0:
        return '{}@{}.{}'.format(firstname, organization, tld)
    elif case == 1:
        return '{}@{}.{}'.format(lastname, organization, tld)
    elif case == 2:
        return '{}{}{}@{}.{}'.format(firstname, separator, lastname, organization, tld)
    elif case == 3:
        return '{}{}{}@{}.{}'.format(firstname, separator, lastname[0], organization, tld)
    elif case == 4:
        return '{}{}{}@{}.{}'.format(firstname[0], separator, lastname, organization, tld)
    elif case == 5:
        return '{}{}{}@{}.{}'.format(firstname[0], separator, lastname[0], organization, tld)
    elif case == 6:
        return '{}{}{}@{}.{}'.format(lastname, separator, firstname, organization, tld)
    elif case == 7:
        return '{}{}{}@{}.{}'.format(lastname, separator, firstname[0], organization, tld)
    elif case == 8:
        return '{}{}{}@{}.{}'.format(lastname[0], separator, firstname, organization, tld)
    elif case == 9:
        return '{}{}{}@{}.{}'.format(lastname[0], separator, firstname[0], organization, tld)

def

if __name__ == "__main__":
    print(permutate_email('John', 'King', 'CNN', case=2))
    for i in range(10):
        print(permutate_email('John', 'King', 'CNN'))
