#Caleb Wastler
import os
from random import randint as rand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#convert a python bytearray to str
def bytesToStr(b):
	return "".join(map(chr, b))
#convert a string to int with same bit representation
def stringToInt(s):
	s=s[::-1]
	i = 0

	bytes_of_str = map(ord,s)

	for p in range(len(bytes_of_str)):
		i+= bytes_of_str[p] * 2**(8*p)

	return i
#convert an int to a string with same bit representation
def intToString(i):
	s=''

	while i != 0:
		#take off next byte
		c = i%2**8
		s+= chr(c)
		i=i>>8
	#prepend null chars if string less than 16B
	return '\x00'*(16-len(s)) + s[::-1]

def CBCenc(key,iv,msg):
	#encryptor for single blocks
	e=Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()

	m = bytearray(msg)
	i = bytearray(iv)
	k = bytearray(key)

	ct_blocks=[]
	last_ct_block=i
	pt_block_start=0
	input_to_PRF = bytearray(16)

	while pt_block_start < len(m):
		#xor next pt block with last ct block
		for b in range(16):
			input_to_PRF[b] = m[pt_block_start+b] ^ last_ct_block[b]
		# input_to_PRF = bytesToStr(m[pt_block_start:pt_block_start+16]^last_ct_block)
		#give to PRF
		last_ct_block = e.update(bytesToStr(input_to_PRF))# + e.finalize()
		#append block to CT
		ct_blocks.append(last_ct_block)
		#convert ct_block to bytearray for next round
		last_ct_block=bytearray(last_ct_block)
		#move index to next block
		pt_block_start+=16

	return ''.join(ct_blocks)

def CBCdec(key,iv,ct):
	#decryptor for single blocks
	d=Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
	#break up ct into blocks
	ct_blocks = [ ct[i:i+16] for i in range(0,len(ct),16)]
	ct_blocks = [iv] + ct_blocks
	pt = []
	pt_block=bytearray(16)

	for b in range(len(ct_blocks)-1,0,-1):
		f_k_inverse = bytearray(d.update(ct_blocks[b]))
		c_min1 = bytearray(ct_blocks[b-1])

		for bit in range(16):
			pt_block[bit] = f_k_inverse[bit] ^ c_min1[bit]

		pt.append(bytesToStr(pt_block))

	return ''.join(pt[::-1])
	
def CTRenc(key,ctr,msg):
	#encryptor for single blocks
	e=Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()

	m = bytearray(msg)
	# c = bytearray(ctr)
	k = bytearray(key)

	ct_blocks=[]
	i=0
	pt_block_start=0	
	next_ct_block = bytearray(16)

	while m!= '':
		#take off the first block of pt
		pt_block = m[pt_block_start:pt_block_start+16]
		m = m[pt_block_start+16:]
		#compute PFR(ctr+blocknumber)
		otp=bytearray(e.update(intToString((stringToInt(ctr)+i)%2**(16*8))))
		i+=1
		#xor the two parts
		for b in range(16):
			next_ct_block[b] = pt_block[b] ^ otp[b]

		ct_blocks.append(bytesToStr(next_ct_block))

	return ''.join(ct_blocks)

def CTRdec(key,ctr,ct):
	#decryptor for single blocks
	e=Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
	#break up ct into blocks
	ct_blocks = [ ct[i:i+16] for i in range(0,len(ct),16)]
	ctr = (stringToInt(ctr)+len(ct_blocks)-1)%2**(16*8)
	pt_block = bytearray(16)
	pt=[]

	for b in range(len(ct_blocks)-1,-1,-1):
		#compute prf(ctr+i)
		f_k_ctr = bytearray(e.update(intToString(ctr)))
		ctr= (ctr-1)%2**(16*8)
		#take the corresponding ct block
		c_b = bytearray(ct_blocks[b])
		#xor the two parts
		for bit in range(16):
			pt_block[bit] = c_b[bit] ^ f_k_ctr[bit]

		pt.append(bytesToStr(pt_block))

	return ''.join(pt[::-1])
#encrypts and decrypts n random vals using CBC and CTR
def demonstrateEncDec(n):
	for r in range(n):
		key = os.urandom(16)
		iv =  os.urandom(16)
		ctr = os.urandom(16)
		msg = ''.join([ os.urandom(16) for i in range(rand(2,5)) ])

		print '#'*8,'Round ',r+1

		print "CBC\t",

		##################### CBC #####################
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		cipher_text = encryptor.update(msg) + encryptor.finalize()

		decryptor = cipher.decryptor()
		plain_text = decryptor.update(cipher_text) + decryptor.finalize()

		Cipher_Text_FROM_YOUR_CBC_IMPLEMENTATION = CBCenc(key, iv, msg)

		assert cipher_text == Cipher_Text_FROM_YOUR_CBC_IMPLEMENTATION
		print 'ct=ct? =>', cipher_text == Cipher_Text_FROM_YOUR_CBC_IMPLEMENTATION,'  |  ',

		pt = CBCdec(key,iv,Cipher_Text_FROM_YOUR_CBC_IMPLEMENTATION)

		assert plain_text == pt
		print 'pt=pt? =>', plain_text == pt

		print "CTR\t",
		##################### CTR #####################
		cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend=default_backend())
		encryptor = cipher.encryptor()
		cipher_text = encryptor.update(msg) + encryptor.finalize()

		decryptor = cipher.decryptor()
		plain_text = decryptor.update(cipher_text) + decryptor.finalize()

		Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION = CTRenc(key, ctr, msg)

		assert cipher_text == Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION
		print 'ct=ct? =>', cipher_text == Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION,'  |  ',

		pt = CTRdec(key,ctr,Cipher_Text_FROM_YOUR_CTR_IMPLEMENTATION)

		assert plain_text == pt
		print 'pt=pt? =>', plain_text == pt
#returns true if pt has valid padding, else false
def paddingOracle(key,iv,ct):
	pt = CBCdec(key,iv,ct)
	padded_bytes = ord(pt[-1])

	valid=True
	for b in range(len(pt)-1,len(pt)-1-padded_bytes,-1):
		if ord(pt[b]) != padded_bytes:
			valid=False
	return valid
#adds 1 to the ith byte of the second to last block of pt
def changeCTbyteIby1(ct,i,num_blocks):
	return ct[:(num_blocks-3)*16+i] + chr((ord(ct[(num_blocks-3)*16+i])+1)%256) + ct[(num_blocks-3)*16+i+1:]
#xors one byte of ct with delta
def xorCTbyteIwithDelta(ct,byte,delta):
	return ct[:byte] + chr(ord(ct[byte])^delta) + ct[byte+1:]
#recovers the last block of a cipher text that is at least 2 blocks long
def paddingAttack(key,iv,ct):
	num_blocks = len(ct)/16
	#open file for logging queries and start counter
	log = open('queryLog.txt','w')
	query_counter=1
	log.write('#'*20 + 'Find Pad Length\n')
	#need to find length of pad
	padded_bytes=16
	mod_ct=changeCTbyteIby1(ct,padded_bytes,num_blocks)
	#find number of padded bytes
	while paddingOracle(key,iv,mod_ct):
		log.write('query %d:\n\\x%x\nresult %r\n'%(query_counter,stringToInt(mod_ct),False))
		query_counter+=1
		padded_bytes+=1
		mod_ct=changeCTbyteIby1(ct,padded_bytes,num_blocks)


	log.write('query %d:\n\\x%x\nresult %r\n'%(query_counter,stringToInt(mod_ct),True))
	padded_bytes= 16-(padded_bytes-16)
	print "message has ",padded_bytes," padded bytes"

	temp_ct = ct
	plain_text = ''
	for b in range((num_blocks-1)*16-padded_bytes-1,(num_blocks-2)*16-1,-1):
		chagepadding = bytearray('\x00'*(((num_blocks-1)*16)-padded_bytes)+str(chr((padded_bytes+1)^padded_bytes))*padded_bytes+'\x00'*16)
		#change the padding bytes to b+1
		mod_ct = bytearray(temp_ct)
		for bit in range(len(ct)):
			mod_ct[bit] = chagepadding[bit]^mod_ct[bit]
		mod_ct = bytesToStr(mod_ct)

		log.write("%sRecovering %dth byte of block %d\n"%('#'*20,16-padded_bytes,num_blocks))
		temp_mod_ct = mod_ct
		delta = 0
		while not paddingOracle(key,iv,temp_mod_ct):
			query_counter+=1
			log.write('query %d:\n\\x%x\nresult %r\n'%(query_counter,stringToInt(temp_mod_ct),False))

			delta+=1
			temp_mod_ct = mod_ct[:len(mod_ct)-padded_bytes-17] + chr(ord(ct[len(mod_ct)-padded_bytes-17])^delta) + mod_ct[len(mod_ct)-padded_bytes-17+1:]

		query_counter+=1
		log.write('query %d:\n\\x%x\nresult %r\n'%(query_counter,stringToInt(temp_mod_ct),True))
		log.write("delta %d produced a valid ct, then the %dth byte of block %d is %c\n"%(delta,16-padded_bytes,num_blocks,chr((padded_bytes+1)^delta)))
		print 'delta:',delta,'produced valid ct => revealed character: ',chr((padded_bytes+1)^delta)		
		plain_text = chr((padded_bytes+1)^delta) + plain_text
		padded_bytes+=1
		temp_ct = mod_ct = temp_mod_ct
		
	log.write("\n\n\n%s\nThe last block of the plain text corresponding to cipher text \\x%x is '%s'\n"%('#'*20+'Final Answer',stringToInt(ct),plain_text))
	print 'Last block of plain_text:',plain_text,'\nAttack required ',query_counter,' queries to the oracle'

	log.close()
	return plain_text
#pads a message with 'b...b'
def pad_msg(s):
	b = 16-len(s)%16
	return s + chr(b)*b

def main():
	demonstrateEncDec(10)

	print "#"*8,'Padding Attack'

	key = os.urandom(16)
	iv =  os.urandom(16)

	padded_message = pad_msg('1234567890123456'*1 +'secret_msg')
	# padded_message = pad_msg('1234567890123456'*2 +'rocket_man')
	# padded_message = pad_msg('1234567890123456'*3 +'secret')

	padded_ct = CBCenc(key,iv,padded_message)

	assert paddingAttack(key,iv,padded_ct) == 'secret_msg'
	# assert paddingAttack(key,iv,padded_ct) == 'rocket_man'
	# assert paddingAttack(key,iv,padded_ct) == 'secret'

	print "For a complete list of queries to the padding oracle see queryLog.txt"

if __name__ == '__main__':
	main()