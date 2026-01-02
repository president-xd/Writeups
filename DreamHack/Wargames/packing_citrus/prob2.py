KEY = b"DELICIOUS"

def box(data):
    res = []
    for i, b in enumerate(data):
        k = KEY[i % len(KEY)]
        res.append(b ^ k ^ (i & 0xFF))
    return bytes(res)