import math, random, sys, socket, subprocess

# Function to factor n given φ(n)
def factors(n, phi_n):
    # Using the relations:
    # p + q = n - φ(n) + 1
    # p * q = n
    sum_pq = n - phi_n + 1
    D = sum_pq * sum_pq - 4 * n  # discriminant = (p+q)^2 - 4n
    if D < 0:
        raise ValueError("Negative discriminant, no integer solution for p and q.")
    sqrtD = math.isqrt(D)
    if sqrtD * sqrtD != D:
        raise ValueError("Discriminant is not a perfect square, cannot factor n.")
    # Solve for p and q:
    p = (sum_pq + sqrtD) // 2
    q = (sum_pq - sqrtD) // 2
    return p, q

# Function to factor n given a multiple of φ(n)
def factors_from_multiple_phi(n, M, trials=300):
    # Write M = 2^t * r with r odd
    t = 0
    r = M
    while r % 2 == 0:
        r //= 2
        t += 1
    # Attempt to find nontrivial factors
    for _ in range(trials):
        a = random.randrange(2, n - 1)
        g = math.gcd(a, n)
        if 1 < g < n:
            # Found a factor by chance
            return g, n // g
        v = pow(a, r, n)
        if v == 1 or v == n - 1:
            # a^r ≡ ±1 (mod n) gives no information, try another a
            continue
        # Check successive squarings v^(2^i)
        for i in range(1, t + 1):
            v_sq = pow(v, 2, n)
            if v_sq == 1:
                # Found a nontrivial square root of 1 mod n
                g = math.gcd(v - 1, n)
                if 1 < g < n:
                    return g, n // g
                # If gcd is 1 or n, break to try a new 'a'
                break
            v = v_sq
            if v == n - 1:
                # Reached -1, go to next a
                break
    raise ValueError("Failed to factor n after many trials; increase trials.")

# Specify remote host/port if using a network connection (otherwise None to run locally)
HOST = None  # e.g. "example.ctf.net"
PORT = None  # e.g. 12345

# Allow host/port to be passed via command-line arguments
if len(sys.argv) >= 3:
    HOST = sys.argv[1]
    try:
        PORT = int(sys.argv[2])
    except ValueError:
        print("Usage: python solution.py [HOST PORT]")
        sys.exit(1)

# Determine mode
use_remote = (HOST is not None and PORT is not None)

# Start challenge process or connect to remote
if use_remote:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((HOST, PORT))
    conn_in = conn.makefile('r', encoding='utf-8', newline='')
    conn_out = conn.makefile('w', encoding='utf-8', newline='')
else:
    # Launch local challenge script with unbuffered output
    CHALLENGE_CMD = ["python3", "-u", "challenge.py"]
    process = subprocess.Popen(CHALLENGE_CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    conn_in = process.stdout
    conn_out = process.stdin

def read_until(pattern):
    """Read lines until a line containing the given pattern is found. Returns that line, or None if EOF."""
    while True:
        line = conn_in.readline()
        if not line:
            return None
        line = line.rstrip('\n')
        if pattern in line:
            return line

# --- Challenge 1: Factor n given φ(n) ---
# Wait for the challenge to output the Challenge 1 prompt
line = read_until("Challenge 1")
n1 = None
phi1 = None
# Read n and φ(n) values
while True:
    line = conn_in.readline()
    if not line:
        print("Failed to read Challenge 1 parameters.")
        sys.exit(1)
    line = line.strip()
    if line.startswith("n ="):
        n1 = int(line.split("=", 1)[1].strip())
    elif line.startswith("phi ="):
        phi1 = int(line.split("=", 1)[1].strip())
    elif line.startswith("input factors"):
        break

# Factor n1 using φ(n1)
try:
    p1, q1 = factors(n1, phi1)
except Exception as e:
    print(f"Error factoring n1: {e}")
    sys.exit(1)
# Send the factors for Challenge 1
conn_out.write(str(p1) + "\n")
conn_out.flush()
conn_out.write(str(q1) + "\n")
conn_out.flush()

# --- Challenge 2: Factor n given a multiple of φ(n) ---
line = read_until("Challenge 2")
n2 = None
M = None
# Read n and the multiple of φ(n)
while True:
    line = conn_in.readline()
    if not line:
        print("Failed to read Challenge 2 parameters.")
        sys.exit(1)
    line = line.strip()
    if line.startswith("n ="):
        n2 = int(line.split("=", 1)[1].strip())
    elif line.startswith("phi ="):
        M = int(line.split("=", 1)[1].strip())
    elif line.startswith("input factors"):
        break

# Factor n2 using the multiple M of φ(n2)
try:
    p2, q2 = factors_from_multiple_phi(n2, M)
except Exception as e:
    print(f"Error factoring n2: {e}")
    sys.exit(1)
# Send the factors for Challenge 2
conn_out.write(str(p2) + "\n")
conn_out.flush()
conn_out.write(str(q2) + "\n")
conn_out.flush()

# --- Challenge 3: Decryption oracle attack ---
line = read_until("Challenge 3")
n3 = None
enc = None
# Read n and the encryption result
while True:
    line = conn_in.readline()
    if not line:
        print("Failed to retrieve Challenge 3 parameters.")
        sys.exit(1)
    line = line.strip()
    if line.startswith("n ="):
        n3 = int(line.split("=", 1)[1].strip())
    elif line.startswith("encryption result ="):
        enc = int(line.split("=", 1)[1].strip())
        # After this line, the challenge is waiting for the crafted ciphertext
        break

if n3 is None or enc is None:
    print("Failed to retrieve Challenge 3 parameters.")
    sys.exit(1)

# Handle the edge case where enc = 0 (this means msg ≡ 0 mod n, likely msg == n)
if enc == 0:
    # If encryption result is 0, the secret message is likely n itself
    msg_recovered = n3
    conn_out.write(str(msg_recovered) + "\n")
    conn_out.flush()
    flag_line = conn_in.readline()
    if not flag_line:
        print("No flag received. It might mean the final answer was incorrect or an error occurred.")
    else:
        print(flag_line.strip())
    # Clean up and exit
    if use_remote:
        conn_in.close(); conn_out.close(); conn.close()
    else:
        process.stdout.close(); process.stdin.close(); process.stderr.close(); process.terminate()
    sys.exit(0)

# Perform the chosen-ciphertext attack using the decryption oracle
e = 65537
r = None
target = None
# Choose a random r until target != enc
while True:
    candidate = random.randrange(2, n3)
    if math.gcd(candidate, n3) != 1:
        continue
    tgt = (enc * pow(candidate, e, n3)) % n3
    if tgt == enc:
        # Avoid r that makes target equal to enc
        continue
    r = candidate
    target = tgt
    break

# Send the crafted ciphertext to the oracle
conn_out.write(str(target) + "\n")
conn_out.flush()
# Receive the oracle's decryption of our crafted ciphertext
line = conn_in.readline()
if not line:
    print("Did not receive decryption result from oracle.")
    sys.exit(1)
line = line.strip()
if line.startswith("decryption result ="):
    oracle_res = int(line.split("=", 1)[1].strip())
else:
    # If formatting is unexpected, try to extract the number
    if "decryption result" in line:
        # e.g., if some prefix or different format
        parts = line.split("=", 1)
        oracle_res_str = parts[1] if len(parts) > 1 else line
    else:
        # Continue reading until we find the line
        oracle_line = read_until("decryption result")
        if not oracle_line:
            print("Did not receive decryption result from oracle.")
            sys.exit(1)
        parts = oracle_line.split("=", 1)
        oracle_res_str = parts[1] if len(parts) > 1 else oracle_line
    oracle_res = int(oracle_res_str.strip())

# Compute the original message: m = oracle_res * r^{-1} mod n3
try:
    r_inv = pow(r, -1, n3)
except TypeError:
    # For Python versions < 3.8, use extended Euclidean algorithm
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = egcd(b % a, a)
        return g, y1 - (b // a) * x1, x1
    g, x, y = egcd(r, n3)
    if g != 1:
        print("Error: r has no modular inverse (gcd != 1).")
        sys.exit(1)
    r_inv = x % n3

msg_recovered = (oracle_res * r_inv) % n3
# Send the recovered message as the final answer for Challenge 3
conn_out.write(str(msg_recovered) + "\n")
conn_out.flush()

# Receive the flag from the challenge
flag_line = conn_in.readline()
if not flag_line:
    print("No flag received. It might mean the final answer was incorrect or an error occurred.")
else:
    print(flag_line.strip())

# Clean up connections
if use_remote:
    conn_in.close()
    conn_out.close()
    conn.close()
else:
    # Read any remaining error output (if any) and terminate the process
    _ = process.stderr.read()
    process.stdout.close()
    process.stdin.close()
    process.stderr.close()
    process.terminate()
