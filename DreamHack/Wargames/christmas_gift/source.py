from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random

e=lambda d:AES.new(
    (lambda s:(
        random.seed(
            (s^0x5a5a5a5a)^(~s&0xffffffff)^((s<<13)&0xffffffff)^((s>>7)&0xff)*0x1010101
        ),
        bytes(
            (random.getrandbits(128)>>(i*8))&255^(s>>(i*3)&0xff)^((s<<(i%5))&0xff)
            for i in range(15,-1,-1)
        )
    )[1])(int.from_bytes(d[:4],'big')),
    AES.MODE_CBC,
    (lambda t:t+b'\x00'*(16-len(t)))(bytes([
        d[0],
        ((d[2]^d[3])*57+131)&255,
        ((d[3]<<3)^(d[2]>>5)^0b10101010)&255,
        *((((v:=d[i])>>(v%7)|v<<(8-v%7))&255)for i in(2,3))
    ]))
).encrypt(pad(d,16))