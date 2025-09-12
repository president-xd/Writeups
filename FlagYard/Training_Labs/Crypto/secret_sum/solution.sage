from Crypto.Util.number import long_to_bytes
import ast

# Read output.txt
with open('output.txt', 'r') as f:
    data = f.read()

# Parse p, q, gA, s
p_str = data.split('p = ')[1].split('\n')[0]
p = int(p_str)
q_str = data.split('q = ')[1].split('\n')[0]
q = int(q_str)
gA_str = data.split('gA = ')[1].split('s = ')[0].strip()
gA = ast.literal_eval(gA_str)
s_str = data.split('s = ')[1].split('\n')[0]
s = int(s_str)

n = p * q
n2 = n**2

# Compute λ = lcm(p-1, q-1)
lambda_n = lcm(p-1, q-1)

# Compute μ for decryption
g_lambda = pow(2, lambda_n, n2)
L_g_lambda = (g_lambda - 1) // n
mu = inverse_mod(L_g_lambda, n)

# Decrypt each gA[i] to get A[i]
A_list = []
for g in gA:
    u = pow(g, lambda_n, n2)
    L_u = (u - 1) // n
    A_i = (L_u * mu) % n
    A_list.append(A_i)

# Decrypt s to get M_n
u_s = pow(s, lambda_n, n2)
L_u_s = (u_s - 1) // n
M_n = (L_u_s * mu) % n

L = len(A_list)
C = 2^100  # Large constant

# Construct lattice basis matrix
M = matrix(ZZ, L+2, L+2)
for i in range(L):
    for j in range(L):
        M[i, j] = 1 if i == j else 0
    M[i, L] = 0
    M[i, L+1] = C * A_list[i]

for j in range(L):
    M[L, j] = 0
M[L, L] = 1
M[L, L+1] = C * (-n)

for j in range(L):
    M[L+1, j] = 0
M[L+1, L] = 0
M[L+1, L+1] = C * (-M_n)

# Apply LLL reduction
reduced = M.LLL()

# Find solution vector
for row in reduced:
    if row[L+1] == 0:
        x_list = list(row[:L])
        if all(x in {0, 1, 2} for x in x_list):
            # Convert ternary digits to integer
            number = 0
            for d in x_list:
                number = number * 3 + d
            flag = long_to_bytes(number)
            print(flag)
            break