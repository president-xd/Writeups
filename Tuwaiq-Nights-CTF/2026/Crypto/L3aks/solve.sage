#!/usr/bin/env sage
"""
Diffie-Hellman challenge solver — Lattice-based (LLL) recovery of shared secret.

The server leaks the top 257 bits of s = g^(ab) mod p and s2 = g^((a+c)b) mod p,
plus the private key c. Since s2 = s * B^c mod p, we set up a lattice to recover
the 255 unknown low bits of s via LLL.
"""

from sage.all import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ===================== Given values from output.txt =====================

p  = 13243062138526201284447970770448985497487835935046195151033172870362190226263571343026139270696938219188495760269911620417720944383208589957958028917476379
A  = 10331308973631968839092765216743782231394793605276590834736084468012812737456052443976282026792492928544325597635939926995749490281509837387751732483722289
B_val = 12804907211022889015278628012415679960043121396540707259624421939419807646452519300380372940419262121964832208229011315629370674083955124625987102911578414

r1 = 760378900730138567523985812784164677484768378525866553519207455906967297645062813186975476419680956655829496837046596277141393914017271133326426899480576
c_val  = 10514128938118845773883292289080487620886740574448840718981396583099184943396464503944071765146807497504664152156644409092109452724863376568702011718657467
AC = 6728044098884395227261710027052934011472520336993419141932012587335669380315574134691696465853321171099100275103675199496004505046836578189688984089099408
r2 = 2997362278023140488456292886638406002550622618115848944703928922011753356376940947542648823845754235109234595450483225545693777310720402100337903455436800

ct_hex = "ee7af60d97f400747d8a7cf609ab64c823b7fb2870fc5dc740927344f223a96837c260731d66b56d8f7206b6de5404f1"
iv_hex = "0f098017c38cffaba366c9a4b9caff79"

# ===================== Step 1: Compute the multiplier t =====================
# s2 = g^{(a+c)b} = g^{ab} * g^{cb} = s * B^c  (mod p)
# So t = B^c mod p, and s2 = s * t mod p
g = 2
t = pow(B_val, c_val, p)

# ===================== Step 2: Set up the lattice =====================
# s  = r1 + x   with 0 <= x < 2^255  (unknown low 255 bits)
# s2 = r2 + y   with 0 <= y < 2^255
# s2 ≡ s * t  (mod p)
#   => (r1 + x) * t ≡ r2 + y      (mod p)
#   => x*t - y       ≡ r2 - r1*t   (mod p)
#
# Let c0 = (r2 - r1*t) mod p.  We need x*t ≡ c0 + y (mod p).
#
# Lattice basis (3×3):
#   [ p,   0,  0 ]
#   [ t,   1,  0 ]
#   [ c0,  0,  K ]
#
# The integer combination (-k, x, -1) produces vector (y, x, -K).
# Since x, y < 2^255 and K = 2^255, this is a short vector that LLL finds.

c0 = (r2 - r1 * t) % p
K  = ZZ(2)**255

M = Matrix(ZZ, [
    [p,  0, 0],
    [t,  1, 0],
    [c0, 0, K]
])

print("[*] Running LLL lattice reduction ...")
L = M.LLL()

# ===================== Step 3: Extract x from the reduced basis =====================
s_found = None

for row in L:
    if row[2] == 0:
        continue
    if abs(row[2]) == K:
        # Determine sign: target vector is (y, x, -K)
        if row[2] == -K:
            x_cand = int(row[1])
            y_cand = int(row[0])
        else:  # row[2] == +K  →  negated vector
            x_cand = int(-row[1])
            y_cand = int(-row[0])

        if 0 <= x_cand < 2**255 and 0 <= y_cand < 2**255:
            s_cand = r1 + x_cand
            # Verify the relation s2 = s * t mod p
            if (s_cand * t) % p == r2 + y_cand:
                s_found = s_cand
                print(f"[+] Recovered shared secret s")
                break

if s_found is None:
    print("[-] LLL did not directly yield s. Trying all basis combinations ...")
    # Brute-force small linear combinations of LLL basis vectors
    for i in range(-2, 3):
        for j in range(-2, 3):
            for k in range(-2, 3):
                v = i * L[0] + j * L[1] + k * L[2]
                if v[2] == 0:
                    continue
                if abs(v[2]) == K:
                    if v[2] == -K:
                        x_cand = int(v[1])
                        y_cand = int(v[0])
                    else:
                        x_cand = int(-v[1])
                        y_cand = int(-v[0])
                    if 0 <= x_cand < 2**255 and 0 <= y_cand < 2**255:
                        s_cand = r1 + x_cand
                        if (s_cand * t) % p == r2 + y_cand:
                            s_found = s_cand
                            print(f"[+] Recovered shared secret s (via combination)")
                            break
            if s_found:
                break
        if s_found:
            break

if s_found is None:
    print("[-] Failed to recover shared secret.")
    exit(1)

# ===================== Step 4: Decrypt the flag =====================
sha1 = hashlib.sha1()
sha1.update(str(s_found).encode('ascii'))
key = sha1.digest()[:16]

iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)

print(f"[+] Flag: {flag.decode()}")
