def padcrypt(idx, m, key):
    a, b, c_coef = 3*2**1024, 5*2**1024, 8*2**1024
    a += idx*2**1024
    b += idx*4**1024
    c_coef += idx*6**1024
    padded_m = a*m*m + b*m + c_coef
    c = pow(padded_m, key.e, key.n)