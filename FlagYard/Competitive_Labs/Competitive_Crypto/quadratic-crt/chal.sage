from secrets import randbits

flag = open('flag.txt', 'rb').read().strip()
assert len(flag) == 64

K.<a> = QuadraticField(-7)
O = K.maximal_order()
m1 = O(randbits(128) * a + randbits(128))
m2 = O(randbits(128) * a + randbits(128))
x = int.from_bytes(flag) * a
y1 = x.mod(m1)
y2 = x.mod(m2)

print(f'{y1 = }')
print(f'{y2 = }')
print(f'{m1 = }')
print(f'{m2 = }')
