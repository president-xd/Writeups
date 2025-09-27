# ALT SOLVE SCRIPT
from Crypto.Util.number import long_to_bytes
from sympy.ntheory.modular import crt

def integer_root(n, e):
    low, high = 0, n
    while low < high:
        mid = (low + high) // 2
        if mid ** e < n:
            low = mid + 1
        else:
            high = mid
    return low if low ** e == n else None

def parse_output(file):
    with open(file, "r") as f:
        lines = f.readlines()
    
    values = {}
    for line in lines:
        if '=' in line:
            key, val = line.split('=', 1)
            values[key.strip()] = int(val.strip())
    return values

data = parse_output("output.txt")

n1 = data["n1"]
n2 = data["n2"]
n3 = data["n3"]
c1 = data["c1"]
c2 = data["c2"]
c3 = data["c3"]
e = data["e"]

# Apply CRT
c, _ = crt([n1, n2, n3], [c1, c2, c3])

# Integer root
m = integer_root(c, e)

if m:
    print("Recovered Message:")
    print(long_to_bytes(m))
else:
    print("Root failed")
