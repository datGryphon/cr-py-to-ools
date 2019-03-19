import math
import random
import sys
import hashlib
import os
import time
import cryptography.hazmat.primitives.ciphers.aead as crypto
import struct
import timeit
from copy import deepcopy
import Queue as queue

##########GLOBALS
NUM_TEST_ROUNDS = 1
PROB_PARAM_MR = 1000
MAX_TRIES_4_PRIME = 1000
sys.setrecursionlimit(1000000)  # long type,32bit OS 4B,64bit OS 8B(1bit for sign)
onlyBlockChain=False

##########Utility Functions
def sha(text):
	return hashlib.sha256(text).digest()

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
		c = i%2**8
		s+= chr(c)
		i=i>>8
	return '\x00'*(16-len(s))+s[::-1]

def noZeroIntToString(i):
	s=''
	while i != 0:
		c = i%2**8
		s+= chr(c)
		i=i>>8
	return s[::-1]

def generate_prime(n,t):
	for i in xrange(t):
		p=random.randint(1,2**(n-1))+2**n
		primeQ = isPrimeMR(p,PROB_PARAM_MR,n)
		if primeQ:
			return p
	return -1

def isPrimeMR(p,t,n):
	if p%2==0: 
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

def egcd(a,b):
	if b==0: 
		return a,1,0
	else:
		g,x,y = egcd(b,a%b)
		return g,y,x-(a//b)*y

''' 
//////////////////////////////////////////////PART (A)
'''
#Class from last project, reused to generate keys
class RSA:
	# initialize RSA
	def __init__(self,N=None,e=None,d=None):
		if N is None:
			self.gen()
		else:
			self.rsamodulus=N
			self.e=e
			self.d=d

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

#basic struct for holding keys, secret or public
class Key:
	def __init__(self,exp=None,N=None):
		self.exp=exp
		self.N=N

def sig(sk,x):
	return pow(stringToInt(sha(x)),sk.exp,sk.N)

def ver(pk,x,s):
	return pow(s,pk.exp,pk.N) == stringToInt(sha(x))

if not onlyBlockChain:
	# test RSA signatures
	for i in range(NUM_TEST_ROUNDS):
		rsa = RSA()
		sk=Key(rsa.d,rsa.rsamodulus)
		pk=Key(rsa.e,rsa.rsamodulus)
		x = random.randint(2,rsa.rsamodulus-1)
		while egcd(stringToInt(sha(intToString(x))),rsa.rsamodulus)[0] != 1: x = random.randint(2,rsa.rsamodulus-1)
		print "Signing X:",x
		s = sig(sk,intToString(x))
		# print sys.getsizeof(s),type(s)
		assert ver(pk,intToString(x),s) 

	print "RSA Signature Test Done."


''' 
//////////////////////////////////////////////PART (B)
'''
def numLeadZeros(h):
	pos=0
	try:
		while h[pos] == '\x00': pos += 1
	except IndexError:
		return len(h)*8

	numZero = pos*8
	c = ord(h[pos])

	if c>127: return numZero #msb of h[pos] is 1
	elif c>63: return numZero+1 #2**7 bit 0
	elif c>31: return numZero+2 #2**7 and 2**6 are 0
	elif c>15: return numZero+3
	elif c>7: return numZero+4
	elif c>3: return numZero+5
	elif c>1: return numZero+6
	elif c>0: return numZero+7

def solPOW(x,n):
	saltDeg=n
	maxSalt = 2**saltDeg
	salt=0
	h = sha(struct.pack(">I",salt)+x)
	while numLeadZeros(h) < n:
		# print salt,saltDeg,numLeadZeros(h)
		if salt == maxSalt:
			# print "Could not find solution with salt <= 2^%d\nContinuing..."%(saltDeg)
			saltDeg+=1
			maxSalt *= 2
		salt+=1
		h = sha(struct.pack(">I",salt)+x)

	return salt
def verPOW(s,x,n):
	return numLeadZeros(sha(struct.pack(">I",s)+x)) >= n

if not onlyBlockChain:
	for i in range(NUM_TEST_ROUNDS):
		dat=os.urandom(16)
		for n in range(5,30,5):
			test = lambda: solPOW(dat,n)
			t=timeit.timeit(test,number=1)
			print "found solution for n=%d in %f seconds"%(n,t)

	for n in range(5,30,5):
		for i in range(NUM_TEST_ROUNDS):
			dat=os.urandom(16)
			s=solPOW(dat,n)
			assert verPOW(s,dat,n)
			print "H(%d || %s) ==\n %s\nAnd has %d>=%d leading zeros"%(s, 
				'0x'+"".join("{:02x}".format(ord(c)) for c in dat),
				'0x'+"".join("{:02x}".format(ord(c)) for c in sha(struct.pack(">I",s)+dat)),
				numLeadZeros(sha(struct.pack(">I",s)+dat)),n
				)

	print "POW Test Done."

''' 
//////////////////////////////////////////////PART (C)
'''
class User:
	def __init__(self):
		rsa = RSA()
		self.sk=Key(rsa.d,rsa.rsamodulus)
		self.pk=Key(rsa.e,rsa.rsamodulus)
	
	def sign(self,x):
		return sig(self.sk,x)

	def verify(self,x,s):
		return ver(self.pk,x,s)

class Block:
	#tx format  [pks,pkr,numtx,[serials],sig]
	def __init__(self,TXs,difficulty,prevH):
		self.txs=TXs
		self.stamp=time.localtime()
		self.prevH=prevH
		self.difficulty=difficulty
		self.findPOW(difficulty)
		self.blockH=self.computeHash()
		self.valid=False
		
	def __str__(self):
		return self.fullBlockToString()

	def blockToString(self):
		return '|___|'+ str(self.difficulty) + '|___|'+ self.prevH + '|___|'+ ''.join(map(str,self.stamp))+ '\n|___|\n' + '\n|___|\n'.join([ 
				''.join([str(tx[0].exp),',',str(tx[0].N),'|',
						str(tx[1].exp),',',str(tx[1].N),'|',
						str(tx[2]),'|']+tx[3]+['|',str(tx[4])]) for tx in self.txs 
		])

	def fullBlockToString(self):
		return '|BLOCK|'+str(self.salt)+self.blockToString()

	def findPOW(self,dif):
		x=self.blockToString()
		self.salt = solPOW(x,dif)

	def computeHash(self):
		return sha('|BLOCK|'+str(self.salt)+self.blockToString())

class Blockchain:
	def __init__(self):
		self.coinList={}

	def genCoins(self,n):
		return [os.urandom(16) for i in range(n)]

	def initLedger(self,user):
		self.coinList[user.pk]=self.genCoins(10)
		cmpctTx= ''.join(map(str,[user.pk.exp,',',user.pk.N,'|'] + [user.pk.exp,',',user.pk.N,'|'] + [10,'|'] + self.coinList[user.pk]))
		
		tx=[user.pk,user.pk,10,
			self.coinList[user.pk],
			user.sign(cmpctTx)
		] 

		b=Block([tx],5,'\x00'*16)
		b.valid=True
		# print "Origin block hash:\n",b.blockH
		self.chain=[b]
		self.chainHeight=1

	def initTxQ(self):
		self.txq=[]

	def genTx(self,sender,pkr,serials):

		if not type(serials) is list:
			serials = [serials]

		cmpctTx=''.join(map(str,[sender.pk.exp,',',sender.pk.N,'|'] + [pkr.exp,',',pkr.N,'|'] + [len(serials),'|'] + serials))
		

		tx=[sender.pk,pkr,len(serials),
			serials,
			sender.sign(cmpctTx)
		]

		self.txq.append(tx)		

	def genBlk(self,miner,T):
		if self.chain[-1].valid:
			newCoins=self.genCoins(10)
			cmpctTx= ''.join(map(str,[miner.pk.exp,',',miner.pk.N,'|'] + [miner.pk.exp,',',miner.pk.N,'|'] + [10,'|'] + newCoins))
			
			#mint transaction
			tx=[miner.pk,miner.pk,10,
				newCoins,
				miner.sign(cmpctTx)
			] 

			#get up to T transactions off the queue
			if len(self.txq)>=T:
				txs = [tx] + self.txq[:T]
				self.txq=self.txq[T:]
			else: 
				txs = [tx] +self.txq[:]
				self.txq=[]

			#new block with txs and current diff and prev hash
			b=Block(txs,self.chainHeight+5,self.chain[-1].blockH)
			self.chain.append(b)
			self.chainHeight+=1

		else: print "Cannot mine block because most recent block has not been verified yet"

	def verBlk(self,chainIndex):
		valid=True
		b=self.chain[chainIndex]

		for tx in b.txs:
			if not ver(tx[0],''.join(map(str,[tx[0].exp,',',tx[0].N,'|'] + [tx[1].exp,',',tx[1].N,'|'] + [tx[2],'|'] + tx[3])),tx[4]):
				print "!!!!!!!!Invalid TX SIG"
				valid=False

		if b.prevH != self.chain[chainIndex-1].computeHash() and chainIndex != 0:
			print "!!!!!!!!Previous block hash does not match"
			valid=False

		if not verPOW(b.salt,b.blockToString(),chainIndex+5):
			print "!!!!!!!!POW not valid"
			valid=False

		alreadySpentInBlock={}

		# #based on the construction of coinList dict, can only confirm double spends in the most recent block
		# if chainIndex==self.chainHeight-1 and not b.valid:

		# print "Checking for double spend"

		for tx in b.txs[1:]: #for each transaction other than the mint
			for serial in tx[3]: #for each serial of the transaction
				if serial in self.coinList[tx[0]]: #check if sender has that coin
					if tx[0] in alreadySpentInBlock: #check if sender has already sent coins in this block
						if serial in alreadySpentInBlock[tx[0]]: #check that user has not already spent that coin in this block
							print "!!!!!!!!Double spent coin in same block"
							valid=False
						else: #otherwise add to list of serials spent by user this block
							alreadySpentInBlock[tx[0]].append(serial)
					else: #otherwise add to list of serials spent by user this block
						alreadySpentInBlock[tx[0]]=[serial]
				else:	#otherwise error, user does not own that coin right now
					print "!!!!!!!!Attempt to spend coin that user does not own or does not exist"
					valid=False

		if valid: #if block is still valid execute coin transfer
			# print "Transfering coins for", len(b.txs),"txs" 
			b.valid=True

			mint=b.txs[0]
			if mint[0] in self.coinList:
				self.coinList[mint[0]]+= mint[3]
			else: self.coinList[mint[0]] = mint[3]

			for tx in b.txs[1:]:
				serials=tx[3]
				#remove coins from sender
				self.coinList[tx[0]] = filter(lambda s: s not in serials, self.coinList[tx[0]])
				#give to receiver
				if tx[1] in self.coinList:
					self.coinList[tx[1]]+=serials
				else: self.coinList[tx[1]]=serials

			return True
		else: 
			print "removing all blocks after ", chainIndex-1
			self.chain = self.chain[:chainIndex]

			for k in self.coinList.keys():
				self.coinList[k] = []

			print "rebuilding coinlist from origin"
			for b in self.chain:
				for tx in b.txs:
					if b.txs.index(tx)==0:
						self.coinList[tx[1]].extend(tx[3])
					else:
						self.coinList[tx[0]] = filter(lambda s: s not in tx[3], self.coinList[tx[0]])
						self.coinList[tx[1]].extend(tx[3])


			self.chainHeight-=1
			return False

		# b.valid=valid
		# return valid

	def checkBalance(self,user):
		if user.pk not in self.coinList:
			return 0,[]
		else: return len(self.coinList[user.pk]),self.coinList[user.pk]




numUsers=3

for i in range(NUM_TEST_ROUNDS):
	print "-"*80,"\nBLOCKCHAIN TEST ROUND ",i+1,"\n",'-'*80
	U=[ User() for u in range(numUsers)] #create N users
	print "Generated Users"

	B = Blockchain()

	print "Initializing Blockchain"

	B.initLedger(U[0])
	B.initTxQ()

	print "Gen TX 3 coins from U_0 to U_1"
	coins=B.checkBalance(U[0])[1][:3]
	B.genTx(U[0],U[1].pk,coins)

	print "U_2 mines a block containing that TX"
	B.genBlk(U[2],2)

	print "Check U_1's balance before block has been confirmed"
	print B.checkBalance(U[1])

	isVal=B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal

	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	
	print "U_0 tries to double spend the coins sent to U_1 in last block and send them to U_2"
	B.genTx(U[0],U[2].pk,coins)
	print "Then tries to mine that block onto the blockchain"
	B.genBlk(U[0],2)
	isVal=B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal

	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	

	print "Block was invalid so coins were not double spent and U_0 gets no block reward"

	print "U_1 tries to send the same coins to U_0 and U_2 in the same block"
	B.genTx(U[1],U[0].pk,coins)
	B.genTx(U[1],U[2].pk,coins)
	print "U_0 mines a block containing the transactions"
	B.genBlk(U[0],2)
	isVal = B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal
	print "Block was not valid so coins not spent and no block reward"

	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	

	print "U_0 wants to send 3 more coins to U_1"
	B.genTx(U[0],U[1].pk,B.checkBalance(U[0])[1][:3])

	print "U_1 mines the block"
	B.genBlk(U[1],2)

	print "U_2 tries to steal the coins by modifying the receiver address"
	B.chain[-1].txs[1][1]=U[2].pk

	isVal=B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal
	print "Block was not valid so no coins spent and no block reward"


	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	

	print "U_0 wants U_1 to THINK he's sending him 3 coins"
	B.genTx(U[0],U[1].pk,B.checkBalance(U[0])[1][:3])

	print "U_1 mines the block"
	B.genBlk(U[1],2)

	print "U_0 tries redirect the coins back to himself"
	B.chain[-1].txs[1][1]=U[0].pk
	tx = B.chain[-1].txs[1]
	B.chain[-1].txs[1][4]=U[0].sign(''.join(map(str,[tx[0].exp,',',tx[0].N,'|'] + [tx[1].exp,',',tx[1].N,'|'] + [tx[2],'|'] + tx[3])))

	isVal=B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal
	print "Block was not valid so no coins spent and no block reward"


	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	

	print "A new user joins the blockchain"
	U.append(User())

	print "U_2 sends the new user, U_3, some (3) coins"
	B.genTx(U[2],U[3].pk,B.checkBalance(U[2])[1][:3])

	print "U_1 mines the block"
	B.genBlk(U[1],2)

	isVal=B.verBlk(B.chainHeight-1)
	print "Block Valid? ->",isVal

	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	
	print "U_3 Balance: "
	print B.checkBalance(U[3])	

	print "Modifying the Previous block will make it and the successive block invalid"
	B.chain[-2].prevH='\x00'*16

	isVal=B.verBlk(0)
	print "Origin Valid? ->",isVal
	isVal=B.verBlk(B.chainHeight-2)
	print "Block1 Valid? ->",isVal

	print "U_0 Balance: "
	print B.checkBalance(U[0])
	print "U_1 Balance: "
	print B.checkBalance(U[1])
	print "U_2 Balance: "
	print B.checkBalance(U[2])	
	print "U_3 Balance: "
	print B.checkBalance(U[3])	

print "Blockchain Test Done."