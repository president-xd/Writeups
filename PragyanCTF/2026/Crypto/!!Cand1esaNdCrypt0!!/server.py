#!/usr/bin/env python3
import sys,os
from secrets import randbelow as r
from Crypto.PublicKey import RSA as R
from Crypto.Util.number import bytes_to_long as L
from dotenv import load_dotenv as D
D()
P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
S=48
A=b"I approve the agreement:\n"
B=b"I authorize the transaction:\n"
F=os.environ.get("FLAG","p_ctf{FLAG}")
def p(x):return x+bytes([len(x)&255])
def g(x,a,b):return (pow(x,3,P)+a*pow(x,2,P)+b*x)%P
n=int(os.environ.get("N","0"),0)
e=int(os.environ.get("E","65537"),0)
d=int(os.environ.get("D","0"),0)
if not n or not d:
 k=R.generate(2048);n,e,d=k.n,k.e,k.d
else:
 k=R.construct((n,e,d))
open("public.pem","wb").write(k.publickey().export_key())
def s(h):return pow(h,d,n)
def v(h,u):return pow(u,e,n)==h
def Rf():
 z=sys.stdin.readline().rstrip("\n").encode()
 if len(z)!=S or any(c<32 or c>126 for c in z):
  print("Invalid suffix.",flush=True);sys.exit(0)
 return z
def M():
 a=r(P);b=r(P);u=0
 print("=== CandlesCake Secure Ordering ===",flush=True)
 print(f"Prime: {hex(P)}",flush=True)
 while 1:
  print("\n1. Sign approval")
  print("2. Execute transaction")
  print("3. Exit")
  sys.stdout.write("> ");sys.stdout.flush()
  c=sys.stdin.readline().rstrip("\n")
  if c=="1":
   if u:print("Quota exceeded.");continue
   print("Suffix:",flush=True)
   x=L(p(A+Rf()))
   h=g(x,a,b)
   print("SIG:",hex(s(h)),flush=True)
   m=r(P)
   if not m:m=1
   print("L =", (m*(a-b))%P,flush=True)
   print("X =", m,flush=True)
   u=1
  elif c=="2":
   print("Suffix:",flush=True)
   x=L(p(B+Rf()))
   print("Signature:",flush=True)
   try:u2=int(sys.stdin.readline().strip(),16)
   except:print("Invalid signature format.");continue
   if v(g(x,a,b),u2):
    print("\nAuthorized!");print(F)
   else:print("\nRejected.")
  elif c=="3":
   print("Goodbye.");break
  else:print("Invalid option.")
if __name__=="__main__":M()
