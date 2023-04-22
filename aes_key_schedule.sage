#!/usr/bin/env sage
# encoding: utf-8
import sys, copy
mk = "0f1571c947d9e8590cb7add6af7f6798"
#mk=   "0f470caf15d9b77f71e8ad67c959d698"
plain = "0123456789abcdeffedcba9876543210"

Sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        )

InverseSbox = (
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
0x21, 0x0c, 0x7d
)
R.<x> = GF(2)[]
F= GF(2).extension(x^8 +x^4 + x^3 + x +1,'a')
a = F.gen()
def mult(a,b):
   a=sage.rings.integer.Integer(a)
   b=sage.rings.integer.Integer(b)
   return ZZ((F(a.digits(2))*F(b.digits(2))).polynomial().list(),2)

#print(mult(enc[0][0],row[0])^^mult(enc[0][1],row[1])^^mult(enc[0][2],row[2])^^mult(enc[0][3],row[3]))
def mix_e(ar):
    ar2=copy.deepcopy(ar)
    enc=[[02,03,01,01],[01,02,03,01],[01,01,02,03],[03,01,01,02]]
    #mult(enc[0][0],row[0])^^mult(enc[0][1],row[1])^^mult(enc[0][2],row[2])^^mult(enc[0][3],row[3])
    #print(mult(enc[0][0],row[0])^^mult(enc[0][1],row[1])^^mult(enc[0][2],row[2])^^mult(enc[0][3],row[3]))
    #print(mult(enc[1][0],row[0])^^mult(enc[1][1],row[1])^^mult(enc[1][2],row[2])^^mult(enc[1][3],row[3]))
    #ar2[0]=mult(enc[0][0],ar[0])^^mult(enc[0][1],ar[4])^^mult(enc[0][2],ar[8])^^mult(enc[0][3],ar[12])
    #print(hex(ar2[0]))
    #ar2[1]=mult(enc[0][0],ar[1])^^mult(enc[0][1],ar[1+4*1])^^mult(enc[0][2],ar[1+4*2])^^mult(enc[0][3],ar[1+4*3])
    #print(hex(ar2[1]))
    
    for i in range(0,4):
    	for j in range(0,4):
	    ar2[i*4+j]=mult(enc[i][0],ar[j+0])^^mult(enc[i][1],ar[j+4])^^mult(enc[i][2],ar[j+8])^^mult(enc[i][3],ar[j+12])
    print("Mix Columns")
    print_ar(ar2)
    return ar2
    #ar2[4]=mult(enc[1][0],ar[0])^^mult(enc[1][1],ar[4])^^mult(enc[1][2],ar[8])^^mult(enc[1][3],ar[12])
    #print(hex(ar2[4]))

def mix_u(ar):
    ar2=copy.deepcopy(ar)
    enc=[[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
    for i in range(0,4):
    	for j in range(0,4):
	    ar2[i*4+j]=mult(enc[i][0],ar[j+0])^^mult(enc[i][1],ar[j+4])^^mult(enc[i][2],ar[j+8])^^mult(enc[i][3],ar[j+12])
    print("UnMix Columns")
    print_ar(ar2)
    return ar2
def hex_2_int_array(in_hex):
    int_array = [int(in_hex[i:i+2],16) for i in range(0,len(in_hex),2)]
    return int_array

def int_array_2_hex(int_array):
    out_hex=''
    for i in int_array:
        out_hex += ("%02X" % i)
    return out_hex

def RotWord(t):
    return [t[1], t[2], t[3], t[0]]

Rcon = (
        [0x01, 0, 0, 0],
        [0x02, 0, 0, 0],
        [0x04, 0, 0, 0],
        [0x08, 0, 0, 0],
        [0x10, 0, 0, 0],
        [0x20, 0, 0, 0],
        [0x40, 0, 0, 0],
        [0x80, 0, 0, 0],
        [0x1b, 0, 0, 0],
        [0x36, 0, 0, 0]
        )


def SubWord(t):
    return Sbox[t]
def UnSubWord(t):
    return InverseSbox[t]

def SubWordList(t):
    return [Sbox[i] for i in t]

def xor_n(a, b, n):
    return [a[i] ^^ b[i] for i in xrange(n)]

def aes_key_schedule(mk):

    w0 = [mk[0], mk[1], mk[2], mk[3]]
    w1 = [mk[4], mk[5], mk[6], mk[7]]
    w2 = [mk[8], mk[9], mk[10], mk[11]]
    w3 = [mk[12], mk[13], mk[14], mk[15]]

    r = []
    r.append(w0)
    r.append(w1)
    r.append(w2)
    r.append(w3)

    for i in range(4, 44):
        temp = r[i-1]
        if ((i % 4) == 0):
            temp = xor_n(SubWordList(RotWord (temp)), Rcon[i/4 -1 ], 4)
        r.append(xor_n(r[i-4], temp, 4))
    ret = []
    for wi in r:
        ret = ret + wi
    return ret

mk_array = hex_2_int_array(mk)
r = aes_key_schedule(mk_array)
print(r," len-> ",len(r),"r[0]",r[0])
print(r[16])
plain='0189fe7623abdc5445cdba3267ef9810'

def print_ar(ar):
    count=0
    for i in ar:
    	sys.stdout.write(format(i,'x')+" ")
	if(count%4==3):
		print("")
	count=count+1
def print_key(round_key,round):
    round=round*16
    for i in range(0,4):
    	sys.stdout.write(str(hex(round_key[0+i+round]))+" ")
	sys.stdout.write(str(hex(round_key[4+i+round]))+" ")
	sys.stdout.write(str(hex(round_key[8+i+round]))+" ")
	sys.stdout.write(str(hex(round_key[12+i+round]))+" ")
	print("")
def shift(ar):
    print("SHIFTY")
    ar2=ar[:]
    ar[7]=ar2[4]
    ar[6]=ar2[7]
    ar[5]=ar2[6]
    ar[4]=ar2[5]
    ar[8]=ar2[10]
    ar[9]=ar2[11]
    ar[10]=ar2[8]
    ar[11]=ar2[9]
    ar[12]=ar2[15]
    ar[13]=ar2[12]
    ar[14]=ar2[13]
    ar[15]=ar2[14]
    print_ar(ar)

def unshift(ar):
    print("UNSHIFTY")
    ar2=ar[:]
    ar[4]=ar2[7]
    ar[7]=ar2[6]
    ar[6]=ar2[5]
    ar[5]=ar2[4]
    ar[10]=ar2[8]
    ar[11]=ar2[9]
    ar[8]=ar2[10]
    ar[9]=ar2[11]
    ar[15]=ar2[12]
    ar[12]=ar2[13]
    ar[13]=ar2[14]
    ar[14]=ar2[15]
    

def aes_encrypt(round_key, plain):
    R.<x>=GF(2)[]
    F = GF(2).extension(x^8 + x^4 + x^3 + x + 1, 'a')
    a=F.gen()
    plain   #'0189fe7623abdc5445cdba3267ef9810'
    ar=map(ord, plain) #.decode('hex'))
    print_ar(ar)
    k=0
    while k < 10:	#each round
    	  round=k*16
	  print("key")
	  print_key(round_key,k)
    	  print("XOR")
    	  for x in range(0,4):
	      #print(ar[x]," "," ",round_key[4*x+16*k])
	      ar[x]=ar[x]^^round_key[4*x+16*k]
	      ar[x+4]=ar[x+4]^^round_key[4*x+1+16*k]
	      ar[x+8]=ar[x+8]^^round_key[4*x+2+16*k]
	      ar[x+12]=ar[x+12]^^round_key[4*x+3+16*k]
	  print_ar(ar)
	  print("SUB-WORD")
    	  for i in range(0,len(ar)):	#SUB-WORD
	      ar[i]=SubWord(ar[i])#.decode('hex')
	  print_ar(ar)
	  shift(ar)
	  if k <9:
	     ar=mix_e(ar)	  
	  k=k+1
    print_key(round_key,k)
    print("Last-XOR")
    for x in range(0,4):
    	#print(ar[x]," "," ",round_key[4*x+16*k])
	ar[x]=ar[x]^^round_key[4*x+16*k]
	ar[x+4]=ar[x+4]^^round_key[4*x+1+16*k]
	ar[x+8]=ar[x+8]^^round_key[4*x+2+16*k]
	ar[x+12]=ar[x+12]^^round_key[4*x+3+16*k]
    print_ar(ar)
    out=""
    for k in ar:
    	out=out+chr(k)
    print("OUT ",out)
    return out
    
def aes_decrypt(round_key, cipher):
    #print("Decrypt")
    R.<x>=GF(2)[]
    F = GF(2).extension(x^8 + x^4 + x^3 + x + 1, 'a')
    a=F.gen()
    ar=map(ord, cipher)
    #print_ar(ar)
    k=10
    while k > 0:
	round=k*16
	#print("key")
	#print_key(round_key,k)
	#print("UN-XOR")
	for x in range(0,4):
	    #print(ar[x]," "," ",round_key[4*x+16*k])																													         ar[x]=ar[x]^^round_key[4*x+16*k]
	    ar[x]=ar[x]^^round_key[4*x+16*k]
	    ar[x+4]=ar[x+4]^^round_key[4*x+1+16*k]
	    ar[x+8]=ar[x+8]^^round_key[4*x+2+16*k]
	    ar[x+12]=ar[x+12]^^round_key[4*x+3+16*k]
	#print_ar(ar)
	if k is not 10:
	   ar=mix_u(ar)
	#print("UNSHIFT")
	unshift(ar)
	#print_ar(ar)
	#print("UN-SUB-WORD")
	for i in range(0,len(ar)):    #SUB-WORD
	    ar[i]=UnSubWord(ar[i])
	#print_ar(ar)
	k=k-1
    for x in range(0,4):
    	#print(ar[x]," "," ",round_key[4*x+16*k])                                                                                                                                                                                                                                            ar[x]=ar[x]^^round_key[4*x+16*k]
	ar[x]=ar[x]^^round_key[4*x+16*k]
	ar[x+4]=ar[x+4]^^round_key[4*x+1+16*k]
	ar[x+8]=ar[x+8]^^round_key[4*x+2+16*k]
	ar[x+12]=ar[x+12]^^round_key[4*x+3+16*k]
    #print_ar(ar)
    out=""
    for k in ar:
    	out=out+chr(k)
    #print("OUT ",out)
    #print("Decrypt-Done")
    return ar

def  aes_encrypt_cbc(iv, round_key, plain):
     if(False):
	print("MAGIC")
     else:
	print("start-Encrypt")
	message=map(ord,  plain[0:16])
	iv_ar=map(ord, iv)
	final=""
	for l in range(0,16):
	    message[l]=iv_ar[l]^^message[l]
	print("Message ",message)
	s=""
	for k in message:
	    s=s+chr(k)
	for k in range(0,len(plain)/16):
	    print("start loop")
	    out=aes_encrypt(round_key, s)
	    print("out",out)
	    final+=out
	    message=map(ord,  plain[(k)*16:(k)*16+16])
	    out_ar=map(ord, out)
	    s=""
	    for l in range(0,16):
	    	s+=chr(out_ar[l]^^message[l])
     print("Final ",final)
     return final

def aes_decrypt_cbc(iv, round_key, cipher):
      print("start-decrypt",cipher)
      final=""
      size=len(cipher)/16
      for k in range(0,size):
      	  out=aes_decrypt(round_key,cipher[(size-1-k)*16:(size-k)*16])
	  print(out,type(out))
	  s=""
	  if(size-1-k==0):
		iv_ar=map(ord, iv)
		print(iv_ar)
		out #=map(ord,  out.decode('hex'))
		for l in range(0,16):
		    out[l]=iv_ar[l]^^out[l]
	  else:
		cipher_ar=map(ord,  cipher[(size-2-k)*16:(size-k-1)*16])
		out  #=map(ord,  out.decode('hex'))
		for l in range(0,16):
		    out[l]=cipher_ar[l]^^out[l]
		    
	  for i in out:
	     s=s+chr(i) 
	  final=s+final
      """message=map(ord,  plain[0:16])
      iv_ar=map(ord, iv)
      #final=""
      for l in range(0,16):
      	  #message[l]=iv_ar[l]^^message[l]
	  print("Message ",message)
	  s=""
      for k in message:
	  s=s+chr(k)
      for k in range(0,len(plain)/16):
	  print("start loop")
	  out=aes_encrypt(round_key, s)
	  print("out",out)
	  final+=out
	  message=map(ord,  plain[(k)*16:(k)*16+16])
	  out_ar=map(ord, out)
	  s=""
	  for l in range(0,16):
	      s+=chr(out_ar[l]^^message[l])"""

      print("Final ",final)
      return final
																										





bagel=aes_encrypt(r, plain)
aes_decrypt(r,bagel)
out=aes_encrypt_cbc("secret12secret21", r, "nopenopehopenopenopenopehopenope")
aes_decrypt_cbc("secret12secret21", r, out)

#xor round numb -> shift -> mix columbtough


