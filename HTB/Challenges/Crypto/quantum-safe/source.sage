r = vector(ZZ, [randint(0, 10) for _ in range(3)])
FLAG = open('flag.txt').read()

pubkey = Matrix(ZZ, [
    [47, -77, -85],
    [-49, 78, 50],
    [57, -78, 99]
])

with open('output.txt', 'w') as f:
    for c in FLAG:
        f.write(f'{vector([ord(c), randint(0, 100), randint(0, 100)]) * pubkey + r}\n')
