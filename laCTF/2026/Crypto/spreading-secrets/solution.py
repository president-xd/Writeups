"""
Shamir Secret Sharing + Deterministic RNG — Solution

The RNG is cubic: state_{n+1} = a*state_n^3 + b*state_n^2 + c*state_n + d (mod p)
Coefficients c_0..c_9 are: c_0 = secret, c_k = g^(k)(secret).
Share at x=1: y1 = sum(c_i) = degree-19683 polynomial in secret.
We build this polynomial and find its roots over GF(p) using FLINT.

Requires: pip install python-flint pycryptodome
"""
import sys, time

# ── Challenge parameters ─────────────────────────────────────────────────────
p  = 12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911
y1 = 6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655

A = 4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159
B = 5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919
C = 4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571
D = 4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027


def solve_flint():
    """Solve using python-flint (FLINT C library — fast polynomial arithmetic)."""
    from flint import fmpz, fmpz_mod_poly_ctx

    ctx = fmpz_mod_poly_ctx(fmpz(p))
    x = ctx([0, 1])  # the polynomial variable

    print("Building polynomial of degree 3^9 = 19683 ...")
    t0 = time.time()

    state = x
    total = x          # running sum, starts with c_0 = s
    cA, cB, cC, cD = ctx([A]), ctx([B]), ctx([C]), ctx([D])

    for i in range(9):
        s2 = state * state
        s3 = s2 * state
        state = cA * s3 + cB * s2 + cC * state + cD
        total += state
        print(f"  step {i+1}/9  deg={state.degree():>5d}  {time.time()-t0:.1f}s")

    f = total - ctx([y1])
    print(f"Polynomial ready — degree {f.degree()}, {time.time()-t0:.1f}s\n")

    print("Finding roots (may take 1-5 min) ...")
    roots = f.roots()
    print(f"Found {len(roots)} root(s) in {time.time()-t0:.1f}s\n")

    for r, _ in roots:
        secret = int(r)
        flag = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
        print(f"  candidate: {flag}")
        if b"lactf" in flag:
            return flag.decode()
    return None


def sage_script():
    """Return a SageMath script the user can paste into sagecell.sagemath.org."""
    return f"""\
# ─── Paste this into https://sagecell.sagemath.org/ ───
p  = {p}
y1 = {y1}
A  = {A}
B  = {B}
C  = {C}
D  = {D}

R.<x> = GF(p)[]
state = x
total = x
for i in range(9):
    state = A*state^3 + B*state^2 + C*state + D
    total += state
    print(f"step {{i+1}}/9  deg={{state.degree()}}")

f = total - y1
print(f"Finding roots of degree-{{f.degree()}} polynomial ...")
roots = f.roots()
for r, m in roots:
    s = int(r)
    flag = s.to_bytes((s.bit_length()+7)//8, 'big')
    print(flag)
"""


if __name__ == "__main__":
    flag = None

    # ── Try python-flint ─────────────────────────────────────────────────
    try:
        flag = solve_flint()
    except ImportError:
        print("python-flint not found — installing ...")
        import subprocess
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "python-flint", "-q"]
            )
            flag = solve_flint()
        except Exception as e:
            print(f"  Installation failed: {e}")
    except Exception as e:
        print(f"python-flint error: {e}")

    # ── Result ───────────────────────────────────────────────────────────
    if flag:
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
    else:
        print("\n" + "="*60)
        print("python-flint did not work on this system.")
        print("Run this SageMath script at https://sagecell.sagemath.org/")
        print("="*60 + "\n")
        print(sage_script())
