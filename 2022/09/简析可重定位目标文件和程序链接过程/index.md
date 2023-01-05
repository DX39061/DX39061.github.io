# 简析可重定位目标文件和程序链接过程


## C源代码到可执行文件

回顾一下从源代码到可执行文件的基本过程

### 预处理（pre-processor)

- 作用：删除注释、文件包含、文本替换、展开宏定义等

- 命令：cpp、gcc -E

- main.c --> main.i

### 编译（compiler）

- 作用：将C源代码编译成汇编代码

- 命令：cc -S、gcc -S

- main.i --> main.s

### 汇编（assembler）

- 作用：将汇编代码转化成`可重定向目标文件`

- 命令：as、gcc -c（编译并汇编）

- main.c --> main.o

### 链接（linker）

- 作用：组合可重定向目标文件，构造可执行文件

- 命令：ld --static（需手动加一堆静态库）

- main.o --> main

## 可重定位目标文件（Relocatable Object Files）

可重定位目标文件是一种ELF（Executable and Linkable Format）文件，由汇编这一步产生。在链接过程中，多个可重定向目标文件被连接器以某一种方式组合，形成最终的可执行文件。

一个可重定向目标文件大致分为三个部分
![1.jpg](/upload/2022/09/1-5e08a2b221c041c997d4d920b500c798.jpg)

### ELF头（ELF Header）

```shell
❯ readelf -h main.o 
ELF 头：  Magic：  7f 45 4c 46 02 01 01 00 01 00 00 00 00 00 00 00 
  类别:                              ELF64
  数据:                              2 补码，小端序 (little endian)
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI 版本:                          1
  类型:                              REL (可重定位文件)
  系统架构:                          Advanced Micro Devices X86-64
  版本:                              0x1
  入口点地址：              0x0
  程序头起点：              0 (bytes into file)
  Start of section headers:          808 (bytes into file)
  标志：             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         14
  Section header string table index: 13
```

ELF header前16个字节中，前四个字节为魔数，第5个字节为文件类型（0x1->32位，0x2->64位），第6个字节为字节序（0x1->小端序，0x2->大端序），第7个字节为ELF版本号，通常都为1，后9个字节未定义，用0填充

### ELF 节（ELF section）

```shell
❯ readelf -S ./main.o # 查看sevtion table
There are 14 section headers, starting at offset 0x328:

节头：  [号] 名称              类型             地址              偏移量       
大小              全体大小          旗标   链接   信息   对齐  
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .text             PROGBITS         0000000000000000  00000040
       0000000000000064  0000000000000000  AX       0     0     1
  [ 2] .rela.text        RELA             0000000000000000  00000220
       0000000000000060  0000000000000018   I      11     1     8
  [ 3] .data             PROGBITS         0000000000000000  000000a4
       0000000000000004  0000000000000000  WA       0     0     4
  [ 4] .bss              NOBITS           0000000000000000  000000a8
       0000000000000000  0000000000000000  WA       0     0     1
  [ 5] .rodata           PROGBITS         0000000000000000  000000a8
       0000000000000003  0000000000000000   A       0     0     1
  [ 6] .comment          PROGBITS         0000000000000000  000000ab
       0000000000000013  0000000000000001  MS       0     0     1
  [ 7] .note.GNU-stack   PROGBITS         0000000000000000  000000be
       0000000000000000  0000000000000000           0     0     1
  [ 8] .note.gnu.pr[...] NOTE             0000000000000000  000000c0
       0000000000000030  0000000000000000   A       0     0     8
  [ 9] .eh_frame         PROGBITS         0000000000000000  000000f0
       0000000000000058  0000000000000000   A       0     0     8
  [10] .rela.eh_frame    RELA             0000000000000000  00000280
       0000000000000030  0000000000000018   I      11     9     8
  [11] .symtab           SYMTAB           0000000000000000  00000148
       00000000000000c0  0000000000000018          12     4     8
  [12] .strtab           STRTAB           0000000000000000  00000208
       0000000000000015  0000000000000000           0     0     1
  [13] .shstrtab         STRTAB           0000000000000000  000002b0
       0000000000000074  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```

- `.text`：存放编译好的机器指令

- `.data`：存放已初始化的全局变量和静态变量

- `.bss`：未初始化的全局变量和静态变量和被初始化为0的全局和静态变量，仅在section table中标记占用总空间，不占据实际空间，程序运行时自动在内存中分配这些变量，并赋0

- `.rodata`：存放只读数据

- `.comment`：存放编译器版本信息

- `.symtab`：Symbol Table 符号表

- `.rel.text`：Relocation Table 重定位表

- `.debug`：调试信息

- `.line`：原始C程序中的行号和.text section中机器指令之间的映射

- `.strtab`：String Table 字符串表，与`.symtab`相比主要用于调试时而不是运行

- `.shstrtab`：section header的字符串表

- `.eh_frame`：gcc处理异常时关于栈展开的记录，[参考阅读](https://www.airs.com/blog/archives/460)

## 静态链接

### 静态库文件

一般后缀为`.a`，一种称为`archive`的特殊文件格式（类似压缩包），是一组可重定位目标文件的集合，如`libc.a`。可使用ar命令解压所有的可重定位目标文件到当前目录

```shell
ar -x /usr/lib/libc.a
```

### 手动构建静态库

```shell
# 使用gcc只编译汇编不链接
gcc -c main.c -o main.o
# 使用ar打包成archive文件，可指定多个.o文件（可重定向目标文件）
ar rcs libmain.a main.o
```

### 使用指定静态库链接

```shell
# 使用gcc静态链接使用指定静态库，后可跟多个，默认添加libc.a
gcc --static -o main main.o ./libmain.a
```

### 符号解析

链接器在链接过程中维护了三个集合：E、U、D，分别是`最终使用的可重定位目标文件`、`引用了但尚未定义的符号`、`已定义的符号`，三个集合初始均为空。

链接开始，链接器从左至右扫描命令行参数，发现可重定位目标文件，就放入集合E，将已定义的符号加入D中，将为定义的符号加入U中。

发现静态库文件，就尝试对库中每一个可重定向目标文件寻找U中未定义的符号，如果找到，则将这个文件加入集合E，相应删除这个文件中包含的U中未定义的符号。将D中没有的、该文件中定义的其他符号加入D中。逐个扫描静态库中的每个可重定向目标文件，如果U中没有对应的为定义的符号，则该文件被丢弃。

所有文件扫描结束后，如果U是空的，则链接器会合并E中的可重定向目标文件来生成可执行文件。如果U非空，则链接器会输出一个错误而中止。

### 重定位

符号解析完成后，连接器会合并各输入模块，为每个符号分配运行时地址

#### 重定位节和符号定义

链接器将多个可重定向目标文件中相同的section合成一个新的section，并为每条指令和全局变量分配运行时地址

#### 重定位节中的符号引用

汇编器在生成可重定位目标文件时，并不知道数据和代码最终放在内存的什么地方，也不知道该模块外引用的外部定义的函数以及全局变量的位置。所以当遇到不确定的符号引用时，汇编器就会生成一个重定向条目，并将不确定的引用地址填0占位。

重定向条目告诉链接器在合成可重定位目标文件时应该如何修改这个引用，`.text`节的重定位条目放在`.rel.text`中。

```c
// 重定位条目的结构
typedef struct {
    long offset;    //被修改的引用的节偏移量
    long type:32,    // 重定位类型l
        symbol:32;    //表示被修改的引用是一个符号
    long addend;    //常数，一些使用进行偏移调整
}ELF64_Rela
```

重定位类型常见的有：重定位绝对引用和重定位相对引用，不详细叙述。

## 动态链接

### 共享库文件

是一种特殊的可重定向目标文件，linux系统中使用`.so`后缀，windows系统中使用`.dll`后缀。动态链接中使用的库文件。在程序鱼形过程中，能被加载到内存的任意地址，还能与一个内存中的程序链接起来。

### 构造共享库

```shell
gcc --shared -fpic -o libmain.so main.c # fpic：生成位置无关代码
```

### 使用指定共享库链接

```shell
gcc -o main main.c ./libmain.so
```

链接器此时并未将libmin.so中的代码和数据复制到可执行文件中，只是复制了一些符号表和重定位信息

当main程序被加载运行时，加载器会发现可执行程序中存在一个名为`.interp`的节，这个节中包含了动态链接器的路径名，实际上这个连接器也是一个共享目标文件（ld-linux.so）。接下来，加载器会将这个动态链接器加载到内存中运行，然后由动态链接器执行重定位代码和数据的工作。

重定位之后，动态链接器把控制权限交给可执行程序。从这以后，共享库的位置就固定了，在程序执行过程中都不会改变

### 在运行时加载共享库

linux系统为动态链接器提供了接口，可以使程序在运行时加载和链接共享库，可使用dlopen、dlsym函数加载，使用dlclose函数卸载。这里不细说了。

