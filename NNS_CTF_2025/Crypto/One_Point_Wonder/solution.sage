import time
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import isPrime

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# Define the field and curve
p = 2*216 * 3*137 - 1
R.<X> = PolynomialRing(GF(p))
F.<i> = GF(p*2, modulus=X*2 + 1)
E = EllipticCurve(F, [1, 0])  # y^2 = x^3 + x

# Given values
j_value = (13897943968670627028821175800566083246788250194739801184755379106763256231540209142346577809447217378788456971272445373264849010133*i + 
           23780011362891232032543058818843206569075289330860563525186623156946237644042578939371224060623299802446529270938546128646375815042)
phiQx = (1438336939527776473524156661440334137208701955112492905069323395488777827834790134059116893010523111877971455504309886416495150015*i + 
         3427726008556100688888416236611350024877356838402910936483689909032270130497153660883916133984220069248107328366037201206313414045)
phiQy = (6796549415058176434426312807671630923318528924038107427972821512510845938594581102460415477288633003544443376494889850457469057366*i + 
         22484510185502283667379549736147041418927205110085658279406360321295482559193327870894913536669477509036655550593482159665400332205)
Px = (7154845853584465773274560285556998041316880875933428625989508840930540660640386605518629576825395103283629863864475785639190189540*i + 
      7055760255797631743070087750378584646385412285826739992132686291867615676943829419672853502757913189891063696683042430994015726061)
iv = bytes.fromhex("d1b026cb22769d8e3ee4a8bfcd16d6e4")
ct = bytes.fromhex("e6c19149e1e8f9b8f7b2cf16233d5b2f19c96b011521114d352d9d6925b4e444c1280eea906716fb3da1080d0194f8db")

# Helper functions
def curve_from_j_over_F(j, F):
    try:
        E0 = EllipticCurve_from_j(j, F)
    except TypeError:
        E0 = EllipticCurve_from_j(j).change_ring(F)
    if isinstance(E0, (list, tuple)):
        E0 = E0[0]
    return E0

def ord3_exponent(T, cap=137):
    U = T
    for e in range(1, cap + 1):
        U = 3 * U
        if U.is_zero():
            return e
    return None

def pick_good_E1(j, x, y, F):
    base = curve_from_j_over_F(j, F)
    A, B = base.a4(), base.a6()
    PR.<T> = PolynomialRing(F)
    poly = B * T*3 + A * x * T2 + (x3 - y*2)
    for idx, (t, mult) in enumerate(poly.roots()):
        A1 = A * t**2
        B1 = B * t**3
        E1_try = EllipticCurve(F, [0, 0, 0, A1, B1])
        if y*2 == x*3 + A1 * x + B1:
            phi_Q_try = E1_try([x, y])
            e_phi = ord3_exponent(phi_Q_try)
            if e_phi is not None:
                return (E1_try, phi_Q_try, e_phi)
    raise ValueError("No suitable curve found")

def dlp_3(A, B, e):
    n = 0
    for i in range(e):
        factor = 3**(e-1-i)
        A_i = factor * A
        B_i = factor * B
        if A_i.is_zero():
            c = 0
        elif A_i == B_i:
            c = 1
        elif A_i == -B_i:
            c = 2
        else:
            raise ValueError("DLP failure")
        n += c * (3**i)
        A = A - c * B
        B = 3 * B
    return n

# Reconstruct E1 and phi_Q with order 3^137
log("Selecting E1 model with phi_Q of order 3^137")
E1, phi_Q, e_phi = pick_good_E1(j_value, phiQx, phiQy, F)
log(f"Selected E1 with j-invariant {E1.j_invariant()}")
log(f"phi_Q has order 3^{e_phi}")

# Walk back the isogeny chain
log("Walking back the isogeny chain")
current_curve = E1
current_point = phi_Q
duals = []
for step in range(137):
    m = 137 - step
    S = (3**(m-1)) * current_point
    if S.is_zero():
        raise ValueError("S is zero")
    if 3*S != current_curve(0):
        raise ValueError("S does not have order 3")
    psi = current_curve.isogeny(S)
    current_curve = psi.codomain()
    current_point = psi(current_point)
    duals.append(psi.dual())
    if (step+1) % 10 == 0:
        log(f"Step {step+1}/137 completed")

log("Isogeny chain walked back successfully")
if not current_curve.is_isomorphic(E):
    raise ValueError("Final curve is not isomorphic to E")

# Compute isomorphism from E to current_curve
iso = E.isomorphism_to(current_curve)

# Generate all possible P points on E considering automorphisms
log("Generating all possible P points on E")
rhs = Px**3 + Px
y_val = rhs.sqrt()
P_candidates = []
for y_sign in [1, -1]:
    y = y_sign * y_val
    P_candidates.append(E([Px, y]))
    P_candidates.append(E([-Px, i*y]))
    P_candidates.append(E([-Px, -i*y]))

# Map P candidates to current_curve
P_mapped = [iso(P) for P in P_candidates]

# Compute forward isogenies
log("Computing forward isogenies")
forwards = list(reversed(duals))

# Compute phi(P) and solve for n
log("Computing phi(P) and solving for n")
for P in P_mapped:
    Q_val = P
    for phi_i in forwards:
        Q_val = phi_i(Q_val)
    A = -Q_val
    B = phi_Q
    try:
        n = dlp_3(A, B, 137)
        if isPrime(n) and n.nbits() == 192:
            key = hashlib.sha256(str(n).encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            pt = unpad(pt, 16)
            if pt.startswith(b'NNS{'):
                log(f"Found n: {n}")
                print(f"Flag: {pt.decode()}")
                sys.exit(0)
    except Exception as e:
        log(f"Error with candidate P: {e}")
        continue

log("Failed to find valid n")