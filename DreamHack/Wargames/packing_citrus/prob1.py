def wrap(data):
    return bytes([(b * 13 + 37) % 256 for b in data])