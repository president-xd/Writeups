from math import gcd, isqrt
import itertools
import sympy
from sympy import Rational
from sympy.ntheory.continued_fraction import continued_fraction, continued_fraction_convergents

n = 74400198359942513862730376031146135802606791991588575465056163121555925617314946580878695576381159966669035646513358312316295727962048929334491638793366454990554957760082895721209907599102882541383389817613899931138405942694622063421798336056156478661669460226638891433547765658851966477956365621503055329677
e = 23
c = 67093879684168042482911544476248580360412038370701084199780323275036434279521774982225923057805337317989111708384627608827582845935869416467560399759225810925388294903783674263633367996837459206550597542374370661621276546154790021615738055122556152562693170717804941676044793478893041430142032267013836633841
pq_high = 10742021914074381086319674056236928469987565979831767505178443989041183736389136816846636592297
ee = 51932890691025605005017310915612916271600777979505331615727718159287280323849710338181794701070147316145187464745426238779347565715981026060820382009264707825630065910448457401066737999090581631520459289158388406640542880406872203650158510808041068826069081102690337835303900100550250976587109590929801721407

bit_shift = 200
sigma_high = pq_high << bit_shift
sigma_approx = sigma_high + (1 << (bit_shift - 1))
phi_approx = n - sigma_approx + 1

cf = continued_fraction(Rational(ee, phi_approx))
conv = list(continued_fraction_convergents(cf))

p = None
q = None

for rat in conv:
    h = rat.p
    l = rat.q
    if l == 0:
        continue
    k = h
    d = l
    if k == 0:
        continue
    if (ee * d - 1) % k != 0:
        continue
    phi = (ee * d - 1) // k
    sigma = n - phi + 1
    disc = sigma ** 2 - 4 * n
    if disc < 0:
        continue
    sqrt_disc = isqrt(disc)
    if sqrt_disc ** 2 != disc:
        continue
    p_cand = (sigma + sqrt_disc) // 2
    q_cand = (sigma - sqrt_disc) // 2
    if p_cand * q_cand == n:
        p = min(p_cand, q_cand)
        q = max(p_cand, q_cand)
        break

if p is None:
    print("Factoring failed.")
else:
    factors = [(p, p-1), (q, q-1)]
    roots_dict = {}
    for prime, phi_prime in factors:
        d_gcd = gcd(e, phi_prime)
        if d_gcd == 1:
            inv = pow(e, -1, phi_prime)
            roots = [pow(c, inv, prime)]
        else:
            q_prime = phi_prime // d_gcd
            if c % prime == 0:
                roots = [0]
            else:
                pow_val = pow(c, q_prime, prime)
                if pow_val != 1:
                    continue
                inv = pow(d_gcd, -1, q_prime)
                x0 = pow(c, inv, prime)
                if pow(x0, e, prime) != c % prime:
                    continue
                zeta = None
                for alpha in range(2, 1000):
                    h = pow(alpha, q_prime, prime)
                    if h != 1:
                        zeta = h
                        break
                if zeta is None:
                    continue
                roots = []
                current = 1
                for j in range(d_gcd):
                    roots.append((x0 * current) % prime)
                    current = (current * zeta) % prime
        roots_dict[prime] = roots

    roots_p = roots_dict[p]
    roots_q = roots_dict[q]

    inv_p_mod_q = pow(p, -1, q)
    inv_q_mod_p = pow(q, -1, p)

    for mp, mq in itertools.product(roots_p, roots_q):
        term1 = mp * q * inv_q_mod_p % n
        term2 = mq * p * inv_p_mod_q % n
        m = (term1 + term2) % n
        try:
            flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            flag = flag_bytes.decode('utf-8')
            if 'FlagY' in flag:
                print(flag)
                break
        except UnicodeDecodeError:
            pass