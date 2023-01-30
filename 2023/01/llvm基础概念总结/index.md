# LLVM基础概念总结


## LLVM的历史

LLVM的命名最早源于**底层虚拟机**（Low Level Virtual Machine）的首字母缩写。后来这个项目不断发展，使得这个名字变得不贴切，于是开发者决定放弃这个缩写的意义。如今LLVM已单纯成为一个品牌，适用于LLVM下的所有项目，包含LLVM中间代码（LLVM IR）、LLVM调试工具、LLVM C++标准库等

## LLVM和编译器

### 常见编译器架构

常见编译器架构通常被分为三部分：

- 前端（Frontend）：词法分析、语法分析、语义分析、生成中间代码

- 中间端优化器（Optimizer）：优化中间代码（有时中间端被归为后端的一部分）

- 后端（Backend）：生成机器码

### LLVM架构

![](https://img.dx3906.cloud/imgs/llvm-1.png)

- 不同的语言使用自己相应的编译前端生成统一的LLVM IR

- LLVM Optimizer对LLVM IR进行优化

- 使用对应平台的LLVM Backend生成相应的机器码

LLVM已经成为多个编译器和代码生成相关项目的子项目。

### LLVM与前端

LLVM最初被用来取代gcc中的代码生成器，gcc的前端许多已经可以与其运行，LLVM目前支持Ada、C、C++、D语言、Fortran、Haskell、Julia、Objective-C、Rust及swift的编译。

LLVM引来一些人为许多语言设计新的编译器。其中比较出名的clang，主要由苹果电脑进行支持，其目的是取代gcc系统下的Objective-C编译器。

### LLVM与中间端

LLVM的核心是中间代码（Intermediate Representation，IR），一种类似于汇编的底层语言。

LLVM IR有三种表示形式：

- 人类可读的形式

- 内存中的LLVM IR

- 二进制形式的bitcode

### LLVM与后端

LLVM已支持多种指令集，可以生成多种平台的机器码。包括ARM、Qualcomm Hexagon、MIPS、Nvidia并行指令集（LLVM中称为NVPTX），PowerPC、AMD TeraScale、AMDGPU、SPARC、SystemZ、RISC-V、WebAssembly、x86、x86-64和XCore

## LLVM作为后端的C语言编译流程

### 一图以蔽之

<img src="https://img.dx3906.cloud/imgs/llvm-2.png" title="" alt="llvm-2.png" width="336">

### 相关文件

- main.c：C语言源代码

- main.ll：LLVM IR的人类可读形式

- main.bc：LLVM IR的bitcode形式。可以使用`lli`解释运行（Just In Time execute）

- main.s：特定平台下的汇编形式

- main.o：可重定向目标文件

- a.out：可执行文件

### 相关工具

- clang：C语言编译前端，用来生成LLVM IR

- opt：llvm IR优化器，针对bitcode形式的IR

- llvm-as：llvm汇编器，将llvm IR人类可读形式转化为bitcode形式

- llvm-dis：llvm-as的逆过程，将bitcode转化为人类可读的形式

- llvm-link：llvm IR bitcode形式的链接器，将多个bitcode文件链接成一个bitcode文件

- llc：llvm IR bitcode形式的编译器，将bitcode转化为汇编代码

- lli：llvm IR bitcode形式的解释运行工具

## Ref

- [LLVM - 维基百科，自由的百科全书](https://zh.wikipedia.org/zh-cn/LLVM)

- [llvm编译的基本概念和流程 | 流水的账](http://blog.throneclay.top/2020/06/23/llvm-note/)

- [深入浅出让你理解什么是LLVM - 简书](https://www.jianshu.com/p/1367dad95445)

- [llvm-ir-tutorial/LLVM IR入门指南(1)——LLVM架构简介.md at master · Evian-Zhang/llvm-ir-tutorial · GitHub](https://github.com/Evian-Zhang/llvm-ir-tutorial/blob/master/LLVM%20IR%E5%85%A5%E9%97%A8%E6%8C%87%E5%8D%97(1)%E2%80%94%E2%80%94LLVM%E6%9E%B6%E6%9E%84%E7%AE%80%E4%BB%8B.md)

