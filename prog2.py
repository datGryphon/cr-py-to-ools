#Caleb Wastler
import math
import random
import sys
import hashlib
import os
import time
import cryptography.hazmat.primitives.ciphers.aead as crypto

sys.setrecursionlimit(1000000)  # long type,32bit OS 4B,64bit OS 8B(1bit for sign)

##########GLOBALS
NUM_TEST_ROUNDS = 1
numFiles=19

##########Utility Functions
def sha(text):
	shaHash = hashlib.sha256()
	shaHash.update(text)
	return shaHash.digest()

def stringToInt(s):
	s=s[::-1]
	i = 0
	bytes_of_str = map(ord,s)

	for p in range(len(bytes_of_str)):
		i+= bytes_of_str[p] * 2**(8*p)
	return i

def intToString(i):
	s=''

	while i != 0:
		#take off next byte
		c = i%2**8
		s+= chr(c)
		i=i>>8
	#prepend null chars if string less than 16B
	return '\x00'*(16-len(s)) + s[::-1]


############## Problem 1 a ##############
PROB_PARAM_MR = 1000
MAX_TRIES_4_PRIME = 1000

# Generate prime number of size n bits
def generate_prime(n,t):
	for i in xrange(t):
		p=random.randint(1,2**(n-1))+2**n
		primeQ = isPrimeMR(p,PROB_PARAM_MR,n)
		if primeQ:
			return p
	return -1

def isPerfPow(N,n):
	for e in range(2,n):
		a=1
		b=N
		while a<=b:
			val = pow((a+b)//2,e)
			if val>N:
				b=((a+b)//2)-1
			elif val<N:
				a=((a+b)//2)+1
			else:
				assert pow((a+b)//2,e) == N
				return (val,e)
	return (-1,-1)

#get number p, test if it's prime using Miller-Rabin
def isPrimeMR(p,t,n):
	if p%2==0: 
		return False
	if n <= 512:
		if isPerfPow(p,n)[0] > 0 :
			return False

	PminOne=p-1
	u=PminOne
	r=0
	while u%2==0:
		u/=2
		r+=1

	for j in xrange(t):
		a = random.randint(2, PminOne)
		val = pow(a, u, p)
		if val != 1: 
			i = 0
			while val != PminOne:
				if i == r-1:
					return False
				else:
					i+= 1
					val = pow(val,2,p) #a^(u*2^i++)
	else: 
		return True

# primality test using the naive approach
def isPrimeNaive(p):
	for i in range(2, int(math.sqrt(p))+2):
		if p % i == 0:
			return False
	return True



#test for 10 small numbers, size n = 20 bits.
for i in range(NUM_TEST_ROUNDS):
	n = 20
	MAX_TRIES_4_PRIME=3*(n**2)
	p=-1
	while p==-1: 
		p = generate_prime(n,MAX_TRIES_4_PRIME)
	if p>0:
		assert isPrimeNaive(p) == True

print "Small Primes Done."

############## Problem 1 b ##############
#adapted from pseudocode I found on 
# https://www.csee.umbc.edu/~chang/cs203.s09/exteuclid.shtml
def egcd(a,b):
	if b==0: 
		return a,1,0
	else:
		g,x,y = egcd(b,a%b)
		return g,y,x-(a//b)*y

class RSA:
	# initialize RSA, generate e, d
	def __init__(self,p=None,q=None,e=None,d=None):
		if p is None:
			self.gen()
		else:
			self.p=p
			self.q=q
			self.rsamodulus=p*q
			self.e=e
			self.d=d
			self.phiN=(p-1)*(q-1)

	# Use generate_prime	
	def gen(self):
		# security parameter
		self.n = 1024

		self.p=self.q=-1
		# Primes p and q
		while self.p==-1: self.p = generate_prime(self.n,3*(self.n**2))
		while self.q == -1 or self.p==self.q: self.q = generate_prime(self.n,3*(self.n**2))
		self.rsamodulus = self.p*self.q
		self.phiN=(self.p-1)*(self.q-1)
		self.d=-1
		while self.d==-1:
			self.e = random.randint(2,self.phiN)
			gcd,self.d,y = egcd(self.e,self.phiN)
			if gcd!=1:
				self.d=-1
				continue
		self.d=self.d%self.phiN	#make sure d>0
	
	def trapdoor(self, x):
		return pow(x,self.e,self.rsamodulus)
	
	def inverse(self, y):
		return pow(y,self.d,self.rsamodulus)

# test RSA, do it 5 times
for i in range(NUM_TEST_ROUNDS):
	rsa = RSA()
	x = random.randint(2,rsa.rsamodulus-1)
	while egcd(x,rsa.rsamodulus)[0] != 1: x = random.randint(2,rsa.rsamodulus-1)
	y = rsa.trapdoor(x)

	assert rsa.inverse(y) == x

print "RSA Test Done."

# ############## Problem 1 c ##############
class ISO_RSA:
	# initialize RSA, generate e, d, ISO RSA implementation
	def __init__(self):
		self.gen()

	def gen(self):
		self.rsa = 	RSA()
		return self.rsa.e,self.rsa.d

	def enc(self, m):
		#choose x in z*_N
		x = random.randint(2,self.rsa.rsamodulus-1) 
		while egcd(x,self.rsa.rsamodulus)[0] != 1: x = random.randint(2,self.rsa.rsamodulus-1)
		y=str(self.rsa.trapdoor(x))
		x=str(x)
		nonce = os.urandom(12)
		aesgcm=crypto.AESGCM(sha(x)[:16])
		ct = aesgcm.encrypt(nonce,m,nonce+y)
		return y,(nonce,ct)
	
	def dec(self, y, c): 
		x = str(self.rsa.inverse(int(y)))
		aesgcm = crypto.AESGCM(sha(x)[:16])
		return aesgcm.decrypt(c[0],c[1],c[0]+y)

# # test ISO RSA, do it 10 times
for i in range(NUM_TEST_ROUNDS):
	m = os.urandom(32) # Generate random messages
	rsa = ISO_RSA()
	y,c = rsa.enc(m)
	assert rsa.dec(y, c) == m

print "ISO RSA Done."

############## Problem 2 ##############
class MerkleNode:
	def __init__(self,fname='',h='',lchil=None,rchil=None):
		self.fname=fname
		self.h=h
		self.lchil=lchil
		self.rchil=rchil

	def __repr__(self):
		return "%s:%s:\n\t(%s,%s)\n"%(self.fname,hex(stringToInt(self.h)),
			self.lchil.__repr__(),	self.rchil.__repr__())

	def __str__(self):
		return self.__repr__()

class MerkleTree:
	def __init__(self):
		pass
	
	def create_tree(self, file_list):
		self.file_list=file_list
		try: #create leaf nodes if they don't already exist
			self.leafNodes
		except AttributeError:
			Nodelist=[]
			for fname in file_list:
				with open(fname,'r') as f:
					n= MerkleNode(fname,sha(f.read()))
					Nodelist.append(n)
			self.leafNodes = Nodelist
		else:
			Nodelist=self.leafNodes

		while len(Nodelist)>1:
			i=0;
			NextList=[]
			while i+2 <= len(Nodelist):
				lchil = Nodelist[i]
				rchil = Nodelist[i+1]
				fname = lchil.fname + rchil.fname
				h = sha(lchil.h + rchil.h)
				par = MerkleNode(fname,h,lchil,rchil)
				NextList.append(par)
				i+=2

			if len(Nodelist)%2!=0:
				NextList.append(Nodelist[-1])

			Nodelist = NextList

		self.root = Nodelist[0].h
		return self.root

	def read_file(self, i):
		fileName = self.file_list[i]
		with open(file_list[i],'r') as f:
			file = f.read() #read file from disk
		Nodelist=self.leafNodes
		#build sibling list on path to root node
		siblings_list = []
		while len(Nodelist)>1:
			i=0;
			NextList=[]
			while i+2 <= len(Nodelist):
				lchil = Nodelist[i]
				rchil = Nodelist[i+1]
				fname = lchil.fname + rchil.fname
				if fname.find(fileName) >= 0: 
					# print "this is a parent node of the file!"
					if (not lchil is None) and lchil.fname.find(fileName)>=0:
						siblings_list.append(('r',rchil.h))
					elif not rchil is None: 
						siblings_list.append(('l',lchil.h))

				h = sha(lchil.h + rchil.h)
				par = MerkleNode(fname,h,lchil,rchil)
				NextList.append(par)
				i+=2

			if len(Nodelist)%2!=0:
				NextList.append(Nodelist[-1])

			Nodelist = NextList

		return (file, siblings_list)
		
	def write_file(self, i, file):
		with open(self.file_list[i],'w') as f:
			f.write(file)
		fhash = sha(file)
		self.leafNodes[i].h = fhash
		return self.create_tree(self.file_list)
		
	def check_integrity(self,i,file,siblings_list):
		workingH = sha(file)
		for side,sib in siblings_list:
			workingH = sha(workingH + sib) if side == 'r' else sha(sib + workingH)
		return workingH == self.root
		
mt = MerkleTree()
#create files for testing
file_list = [ "testFile%d.txt"%(i+1) for i in range(numFiles)  ]
for fname in file_list:
	with open(fname,'w') as f:
		f.write("This is test file %s"%(fname))

mt.create_tree(file_list)
#read and check integrity test
for i in range(NUM_TEST_ROUNDS):
	pos = random.randint(0,numFiles-1)	#pick random file
	file, siblings_list =  mt.read_file(pos)	#read it
	valid = mt.check_integrity(pos,file,siblings_list) 
	assert valid == True	#assert that the file+sibling list generate the root hash
#check integrity test
for i in range(NUM_TEST_ROUNDS):
	pos = random.randint(0,numFiles-1)	#pick random file
	file, siblings_list =  mt.read_file(pos)
	file = intToString(random.randint(0,2**(16*8)-1)) #random 16B int converted to string
	valid = mt.check_integrity(pos,file,siblings_list) 
	assert valid == False	#assert that randomfile + sibling list does not match root node
#write file test
for i in range(NUM_TEST_ROUNDS):
	pos = random.randint(0,numFiles-1)	#pick random file
	new_file = intToString(random.randint(0,2**(16*8)-1)) #random 16B int converted to string
	mt.write_file(pos,new_file)	#write new random data to file
	# Read file and check integrity
	file, siblings_list =  mt.read_file(pos) #read the new file
	valid = mt.check_integrity(pos,file,siblings_list) 
	assert file == new_file and valid == True #assert that the data was successfully committed and the new root hash matches

map(os.remove,file_list) #remove test files

print "Merkle Test Done."
