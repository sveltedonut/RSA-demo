# -*- coding: utf-8 -*-
import sys
from Tkinter import *
import math
import random
import ast

def findPrimes(limit): #crible d'eratosthene: on trouve tous les nombres premiers en bas d'un numbre x
    if limit <= 10: #l'on connait les nombres premiers plus bas que 10
        return [2, 3, 5, 7]
    else:
        primes = findPrimes(round(math.sqrt(limit))) #on trouve tous les nombres premiers plus bas que la racine de x
        primeschk = primes[:]
        for i in range(int(math.sqrt(limit)/2), int(limit/2) + 1): #on cycle a travers tous les nombres entre la racine de x et x
            for j in primeschk: #on verifie si un certain nombre i peut etre divisible par les nombres premiers en bas de la racine de x
                if (i*2+1)%j == 0: #Si oui, i n'est pas premier
                    break
            else: #S'il n'est pas divisible par un nombre premier, il est premier
                primes.append(i*2+1) #on ajoute i a notre liste de nombres premiers
        return primes
        
def primeGen(limit): #on genere deux nombres premiers aleatoires p et q
    primesList = findPrimes(limit)
    p = primesList[random.randint(0, len(primesList)-1)]
    q = primesList[random.randint(0, len(primesList)-1)]
    while p == q: #Si p et q sont egaux, on reessaye jusqu'a ce qu'on obtient deux nombres differents
        q = primesList[random.randint(0, len(primesList)-1)]
    return (p, q)
    
def gcd(a, b): #Calcule le plus grand denominateur commun (PGCD)
    while b:
        a, b = b, a%b
    return a
    
def findCoprimes(phi): #Trouve une liste de nombres plus petit que phi qui est aussi premier par rapport a phi
    coprimes = []
    for i in range (1, phi):
        if gcd(i, phi) == 1:
            coprimes.append(i)
    return coprimes

def findFactors(n):
    primeFactors = []
    d = 2
    while d*d <= n:
        if (n % d) == 0:
            primeFactors.append(d)
        d += 1
    if n > 1:
       primeFactors.append(n)
    return primeFactors
     
def findCoprimes2(phi): #Trouve une liste de nombres plus petit que phi qui est aussi premier par rapport a phi
    coprimes = []
    for i in range(1, phi):
        if gcd(i, phi) == 1:
            coprimes.append(i)
    return coprimes
    
def publicKeyGen(pq): #Genere une cle publique (n, e); l'argument pq est un 2-uplet ou pq[0] = p et pq[1] = q
    coprimesList = findCoprimes2((pq[0] - 1) * (pq[1] - 1))
    e = coprimesList[random.randint(0, len(coprimesList)-1)] #Choisit un nombre aleatoire parmi tous les nombres premiers par rapport a (p - 1)*(q - 1)
    n = pq[0] * pq[1]
    return (n, e)
    
def lcm(a, b): #Calcule le plus petit multiple commun
    lcm = max(a, b)
    while(True):
        if (lcm%a == 0) and (lcm%b == 0):
            return lcm
        lcm += 1 #on verifie chaque nombre a partir du nombre le plus grand jusqu'a ce que l'on trouve un multiple commun.
    
def inverse(e, l): #Trouve un nombre qui satisfait (e * d)mod(l) = 1
    a, b = 0, 1
    u, v = l, e
    while v != 0:
        q = u / v
        a, b = b, a - q * b
        u, v = v, u - q * v
    if a < 0:
        a += l
    return a
    
def privateKeyGen(pq, publicKey): #Genere une cle privee compose de (n, d)
    l = lcm(pq[0] - 1, pq[1] - 1)
    d = inverse(publicKey[1], l)#Choisit un nombre aleatoire qui satisfait (e * d)mod(l) = 1
    return (pq[0] * pq[1], d)
    
def keyGen(limit): #Fonction recapitulatif qui automatise la generation des cles publique (n, e) et privee (n, d)
    pq = primeGen(limit)
    publicKey = publicKeyGen(pq)
    privateKey = privateKeyGen(pq, publicKey)
    return (publicKey, privateKey, pq)

def encode(message, key): #Mecanisme de base auquel l'on peut encoder un nombre
    return (message**key[1])%key[0]
    
def decode(data, key): #Mecanisme de base auquel l'on peut decoder un nombre encode
    return (data**key[1])%(key[0])

def RSAencode(message, key): #Mecanisme d'encodage qui requiert moins de memoire quant a l'ordinateur
    result = 1
    n, e = key
    message = message % n
    while e > 0:
        if e % 2 == 1:
            result = (result * message) % n
        e = e >> 1
        message = (message * message) % n
    return result
    
def RSAdecode(message, key): #Mecanisme de decodage
    result = 1
    n, d = key
    message = message % n
    while d > 0:
        if d % 2 == 1:
            result = (result * message) % n
        d = d >> 1
        message = (message * message) % n
    return result
    
def OTPencodeChar(char):    #Encodage de masque jetable
    pad = random.randint(0, 2**8)
    ecd = (ord(char) + pad) % (2**8)
    code = (pad << 8) + ecd
    return code
        
def OTPdecodeChar(code): #Decodage de masque jetable
    pad = (code >> 8)
    ecd = code - (pad << 8)
    char = chr((ecd - pad) % (2**8))
    return char
    
def OTPencodeStr(message):
    code = []
    for c in message:
        code.append(OTPencodeChar(c))
    return code
    
def OTPdecodeStr(code):
    message = ''
    for c in code:
        message += OTPdecodeChar(c)
    return message
    
def RSAencodeStr(message, key): #Encodage cumulatif de RSA et de masque jetable
    code = []
    for c in message:
        otp = OTPencodeChar(c)
        rsa = RSAencode(otp, key)
        code.append(rsa)
    return code

def RSAdecodeStr(code, key): #Décodage cumulatif de RSA et de masque jetable
    message = ''
    for c in code:
        rsa = RSAdecode(c, key)
        otp = OTPdecodeChar(rsa)
        message += otp
    return message
    
#Interface visuel

master = Tk()
master.title("Encoding/Decoding")
keygen = Tk()
keygen.title("Key Generator")

def callback():
    message = str(ms.get(1.0, END))
    key = ast.literal_eval(ek.get())
    code = RSAencodeStr(message, key)
    ct.config(state=NORMAL)
    ct.delete(1.0, END)
    ct.insert(END, code)
    ct.config(state=DISABLED)
    
def callbackd():
    code = ast.literal_eval(cx.get(1.0, END))
    key = ast.literal_eval(dk.get())
    message = RSAdecodeStr(code, key)
    nm.config(state=NORMAL)
    nm.delete(1.0, END)
    nm.insert(END, message)
    nm.config(state=DISABLED)
    
def callbackk():
    key = keyGen(int(e.get()))
    print key
    pubN.config(state=NORMAL)
    pubN.delete(1.0, END)
    pubN.insert(END, str(key[0]))
    pubN.config(state=DISABLED)
    prvN.config(state=NORMAL)
    prvN.delete(1.0, END)
    prvN.insert(END, str(key[1]))
    prvN.config(state=DISABLED)
    p.config(state=NORMAL)
    p.delete(1.0, END)
    p.insert(END, str(key[2]))
    p.config(state=DISABLED)

t = Label(master, text="RSA encryption")
t.grid(row = 0)
kl = Label(master, text="Encoding key:")
kl.grid(row = 1, column = 0)
ek = Entry(master)
ek.grid(row = 2, column = 0)
ml = Label(master, text="Message:")
ml.grid(row = 5, column = 0)
ms = Text(master, height = 10, width = 50)
ms.grid(row = 6, column = 0)
en = Button(master, text="Encrypt!", command=callback)
en.grid(row = 7, column = 0)
cl = Label(master, text="Ciphertext:")
cl.grid(row = 8, column = 0)
ct = Text(master, height = 10, width = 50)
ct.grid(row = 9, column = 0)
ct.config(state=DISABLED)

nl = Label(master, text="Decoding key:")
nl.grid(row = 1, column = 1)
dk = Entry(master)
dk.grid(row = 2, column = 1)
tl = Label(master, text="Ciphertext:")
tl.grid(row = 5, column = 1)
cx = Text(master, height = 10, width = 50)
cx.grid(row = 6, column = 1)
dc = Button(master, text="Decrypt!", command=callbackd)
dc.grid(row = 7, column = 1)
dm = Label(master, text="Message:")
dm.grid(row = 8, column = 1)
nm = Text(master, height = 10, width = 50)
nm.grid(row = 9, column = 1)
nm.config(state=DISABLED)

t = Label(keygen, text="RSA key Generator")
t.grid(row = 0, column = 3)
l = Label(keygen, text="Upper limit for p and q:")
l.grid(row = 1, column = 3)
e = Entry(keygen)
e.insert(0, 10)
e.grid(row = 1, column = 4)
lpbn = Label(keygen, text="Public Key")
lpbn.grid(row = 2, column = 1)
pubN = Text(keygen, height = 1, width = 20)
pubN.grid(row = 2, column = 2)
pubN.config(state=DISABLED)
lpvn = Label(keygen, text="Private Key")
lpvn.grid(row = 2, column = 3)
prvN = Text(keygen, height = 1, width = 20)
prvN.grid(row = 2, column = 4)
prvN.config(state=DISABLED)
lp = Label(keygen, text="Private Key p & q")
lp.grid(row = 2, column = 5)
p = Text(keygen, height = 1, width = 20)
p.grid(row = 2, column = 6)
p.config(state=DISABLED)

b = Button(keygen, text="Generate!", command=callbackk)
b.grid(row = 4, column = 3)

mainloop()