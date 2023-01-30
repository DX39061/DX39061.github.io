# 函数调用、花指令与smc


## 函数调用

以下以x86汇编为例。

### #栈

从两个角度去理解栈的概念：

- 数据结构：后进先出（last-in-first-out）的一种数据结构
  
  ![栈jpeg](https://img.dx3906.cloud/imgs/%E6%A0%88.jpeg)

- 二进制程序：程序中用来存储局部变量和返回地址的一块连续内存
  
  在pwndbg(增强版gdb)中使用`vmmap`指令可以查看程序内存空间。可以看见有一段属于栈空间

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555555000 r--p     1000 0      /home/dx3906/Documents/REV组会/1-15/function_call/main
    0x555555555000     0x555555556000 r-xp     1000 1000   /home/dx3906/Documents/REV组会/1-15/function_call/main
    0x555555556000     0x555555557000 r--p     1000 2000   /home/dx3906/Documents/REV组会/1-15/function_call/main
    0x555555557000     0x555555558000 r--p     1000 2000   /home/dx3906/Documents/REV组会/1-15/function_call/main
    0x555555558000     0x555555559000 rw-p     1000 3000   /home/dx3906/Documents/REV组会/1-15/function_call/main
    0x7ffff7d95000     0x7ffff7d97000 rw-p     2000 0      [anon_7ffff7d95]
    0x7ffff7d97000     0x7ffff7db9000 r--p    22000 0      /usr/lib/libc.so.6
    0x7ffff7db9000     0x7ffff7f14000 r-xp   15b000 22000  /usr/lib/libc.so.6
    0x7ffff7f14000     0x7ffff7f6b000 r--p    57000 17d000 /usr/lib/libc.so.6
    0x7ffff7f6b000     0x7ffff7f6f000 r--p     4000 1d4000 /usr/lib/libc.so.6
    0x7ffff7f6f000     0x7ffff7f71000 rw-p     2000 1d8000 /usr/lib/libc.so.6
    0x7ffff7f71000     0x7ffff7f80000 rw-p     f000 0      [anon_7ffff7f71]
    0x7ffff7fc4000     0x7ffff7fc8000 r--p     4000 0      [vvar]
    0x7ffff7fc8000     0x7ffff7fca000 r-xp     2000 0      [vdso]
    0x7ffff7fca000     0x7ffff7fcb000 r--p     1000 0      /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7fcb000     0x7ffff7ff1000 r-xp    26000 1000   /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ff1000     0x7ffff7ffb000 r--p     a000 27000  /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000 31000  /usr/lib/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000 33000  /usr/lib/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000 0      [vsyscall]
```

### #寄存器

- esp（extended stack pointer）：指向栈顶

- ebp（extended base pointer）：指向栈底，栈基址

- eip（extended instruction pointer）：指向下一条要执行的指令

### #push & pop

- push var：将var入栈。先`esp -= 4`，然后向esp指向的地方写入xxx

- pop reg：将栈顶元素出栈存在reg中。从esp指向的地方取4字节值，放到reg中，然后`esp += 4`

![pushpoppng](https://img.dx3906.cloud/imgs/push_pop.png)

### #函数调用过程

1. 调用函数：
   
   ```nasm
   call sub_xxx    ; push eip， eip = xxx
   ```

2. 初始化栈：
   
   ```nasm
   push ebp        ; 保存调用函数栈基址
   mov ebp, esp    ; 开启空的新栈
   sub esp, xxx    ; 给局部变量预留空间
   ```

3. 执行函数体：
   
   函数返回值会保存在eax中

4. 函数返回：
   
   ```nasm
   leave        ; mov esp, ebp    
              ; pop ebp
   retn         ; pop eip
   ```

5. 调用者清理调用时栈上分配的参数（cdecl）
   
   ```nasm
   add esp, xxx
   ```

以一个简单的C程序为例：

```c
#include <stdio.h>

int add(int a, int b) {
    int sum;
    sum = a + b;
    return sum;
}

int main() {
    int a = 1, b = 2;
    int c = 3;
    printf("%d", add(a, b) + c);
    return 0;
}
```

gcc编译：`gcc -o main -m32 main.c`

分析`add`函数调用过程栈和寄存器的变化：

![栈png](https://img.dx3906.cloud/imgs/%E6%A0%88.png)

### #调用约定

参考：[X86调用约定 - 维基百科，自由的百科全书](https://zh.m.wikipedia.org/zh-hans/X86%E8%B0%83%E7%94%A8%E7%BA%A6%E5%AE%9A)

微软就喜欢搞事情

X86：

- cdecl（C declaration）：C语言的事实上的标准。参数从右至左入栈，调用者清理栈上参数。

- stdcall：Windows API的标准调用约定。参数从右往左入栈，被调用者清理栈上参数。

- pascal：基于Pascal语言的调用约定。参数从左至右入栈，被调用者清理栈上参数。

X64：

与X86的区别主要是前6个参数使用寄存器传递。

- 微软x86-64调用约定：使用RCX, RDX, R8, R9四个寄存器用于存储函数调用时的4个参数(从左到右)，使用XMM0, XMM1, XMM2, XMM3来传递浮点变量。其他的参数直接入栈(从右至左)。整型返回值放置在RAX中，浮点返回值在XMM0中。

- System V AMD64 ABI：主要在Solaris，GNU/Linux，FreeBSD和其他非微软OS上使用。头六个整型参数放在寄存器RDI, RSI, RDX, RCX, R8和R9上；同时XMM0到XMM7用来放置浮点变元.

## SMC与花指令

### #逆向与反逆向的博弈

- 逆向：一般是指从**二进制文**件倒推回**源代码**进行分析的过程

- 反逆向：开发人员为了避免软件被随意修改，想出了一系列方法，在**不影响软件使用**的前提下，提高软件的逆向分析难度

### #两种基础的反逆向手段

- SMC

- 花指令

### #Self-Modifying Code

- 即代码自修改技术，简称SMC

- 当你直接用IDA打开查看源码时，被修改的部分会呈现出乱码的状态，程序在运行过程中会执行一段修改自身的代码，使得这部分代码变成正确的指令，从而正确执行

- 我们要做的就是通过分析程序未加密的部分，找到用来修改自身的那部分代码，然后手动进行修复并解密

特征：乱码，virtualprotect（PE）、mprotect（ELF），将函数作为地址进行运算

### #花指令

- 由设计者特别构思，希望使反汇编的时候出错，让破解者无法清楚正确地反汇编程序的内容，迷失方向

- 直接导致的结果就是，会使IDA的自动分析失败，产生大量未知数据

- 这时就需要我们来识破这些花指令，引导IDA正常地分析

举例：

- 垃圾字节：最常见

```nasm
jz/jnz    xxx+1
call      xxxx     ; 一般是不存在的地址    
```

- 纯垃圾代码：ransomware

```nasm
pusha
popa
nop
push eax
pop eax
push ebx
pop ebx
```

- 扰乱堆栈平衡的垃圾代码：eflo

```nasm
pop     rax
add     rax, 1
push    rax
mov     rax, rsp
xchg    rax, [rax]
pop     rsp
mov     [rsp], rax
retn
```

- ret实现隐式跳转：

```nasm
push    rbx
pushfq
call    $+5
pop     rbx
add     rbx, 3Fh
mov     [rsp+8], rbx
popfq
retn
```

思路来源：[NCTF2022](https://github.com/X1cT34m/NCTF2022)的ccccha

如何制作：[ret跳转的简单控制流混淆 - DX3906‘s blog](https://blog.dx39061.top/2022/12/%E5%88%A9%E7%94%A8%E8%BF%94%E5%9B%9E%E5%9C%B0%E5%9D%80%E8%BF%9B%E8%A1%8Cret%E8%B7%B3%E8%BD%AC%E7%9A%84%E7%AE%80%E5%8D%95%E6%8E%A7%E5%88%B6%E6%B5%81%E6%B7%B7%E6%B7%86/)

如何去除：[NCTF2022 ccccha 花指令/混淆 详解 - DX3906's blog](https://blog.dx39061.top/2022/12/nctf2022-ccccha-wp/)

