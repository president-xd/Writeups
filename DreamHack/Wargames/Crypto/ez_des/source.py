from flask import Flask, send_file, make_response, render_template_string
from Crypto.Cipher import DES
import random
import time
import os

app = Flask(__name__)

FLAG_FILE = 'flag.txt'
KEY_FILE = 'keys.txt'
CIPHER_FILE = 'ciphertext.txt'
BLOCK_SIZE = 8
NUM_BLOCKS = 50


def read_flag(filename=FLAG_FILE, target_len=400):
    with open(filename, 'rb') as f:
        flag = f.read()
    if len(flag) < target_len:
        flag += b'A' * (target_len - len(flag))
    return flag[:target_len]


def read_keys(filename=KEY_FILE):
    with open(filename, 'r') as f:
        lines = f.readlines()
    keys = [bytes.fromhex(line.strip()) for line in lines if line.strip()]
    assert len(keys) == NUM_BLOCKS and all(len(k) == 8 for k in keys)
    return keys


def split_blocks(msg, block_size=BLOCK_SIZE):
    return [msg[i:i+block_size] for i in range(0, len(msg), block_size)]


def triple_des_ede(block, key):
    c1 = DES.new(key, DES.MODE_ECB).encrypt(block)
    c2 = DES.new(key, DES.MODE_ECB).decrypt(c1)
    c3 = DES.new(key, DES.MODE_ECB).encrypt(c2)
    return c3


def encrypt_flag(plaintext, keys, seed):
    idxs = list(range(NUM_BLOCKS))
    random.seed(seed)
    random.shuffle(idxs)
    blocks = split_blocks(plaintext, BLOCK_SIZE)
    ciphertext_blocks = []
    for i, block in enumerate(blocks):
        key = keys[idxs[i]]
        ct = triple_des_ede(block, key)
        ciphertext_blocks.append(ct)
    return b''.join(ciphertext_blocks)


@app.route('/')
def home():
    return render_template_string('''
        <h2>다운로드</h2>
        <form action="/download">
            <button type="submit">ciphertext.txt 다운로드</button>
        </form>
        <form action="/keys">
            <button type="submit">keys.txt 다운로드</button>
        </form>
    ''')


@app.route('/download')
def download_ciphertext():
    pt = read_flag()
    keys = read_keys()
    seed = int(time.time())
    ct = encrypt_flag(pt, keys, seed)
    tmpfile = 'ciphertext.txt'
    with open(tmpfile, 'wb') as f:
        f.write(ct)
    os.utime(tmpfile, (seed, seed))
    resp = make_response(send_file(tmpfile, as_attachment=True))
    resp.headers['X-Used-Seed'] = str(seed)
    return resp


@app.route('/keys')
def download_keys():
    return send_file(KEY_FILE, as_attachment=True)


if __name__ == '__main__':
    app.run(host="0.0.0.0")
