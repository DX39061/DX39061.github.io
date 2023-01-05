# linux ptrace相关技术（一）基本概述与ptrace函数


## linux ptrace技术（一）基本概述与函数参数

## ptrace概述

逆向壬应该都对ptrace并不陌生，常出现于ELF文件的反调试中。

ptrace其实是linux的一种系统调用，一般用于调试技术。使用ptrace可以实现父进程对子进程的监控和控制，由此开发了动态分析工具如strace和gdb。因为同一时间一个子进程只能被唯一的父进程追踪，所以代码内调用ptrace看能否成功附加到主进程，可以用来检验是否有调试器附加到主进程，起到反调试的作用。

## ptrace函数原型及参数

```c
#include <sys/ptrace.h>       
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

- request：要进行的ptrace操作
- pid：要操作的进程号
- addr：要监控/修改的内存地址
- data：要读取/写入的数据变量

常见request类型：

- PTRACE_TRACE: 表示本进程希望被父进程跟踪, 主动与父进程建立追踪机制

- PTRACE_PEEKTEXT, PTRACE_PEEKDATA: 从addr指定的内存地址中取出数据

- PTRACE_POKETEXT, PTRACE_POKEDATA: 向addr指定的内存地址中写入数据

- PETRACE_PEEKUSER: 从USER结构体中，偏移量为addr处取出数据

- PETRACE_POKEUSER: 向USER结构体中，偏移量为addr处写入数据

- PTRACE_CONT: 使子进程继续运行

- PTRACE_KILL: 杀掉子进程

- PTRACE_SINGLESTEP: 子进程单步执行

- PTRACE_ATTACH: 父进程和子进程建立追踪关系，并发送SIGSTOP信号使其暂停

- PTRACE_DETACH: 父进程解除对子进程的追踪关系，让子进程继续运行

- PTRACE_SEIZE: 父进程对子进程建立追踪关系，但不会让子进程暂停，且要指定data参数`ptrace(PTRACE_SEIZE, pid, 0, PTRACE_0_flags);`

- PTRACE_SYSCALL: 使被停止的子进程继续运行，并在下次进入或退出系统调用时停止。

## Reference

https://stackoverflow.com/questions/9803908/difference-between-ptraceptrace-peekuser-and-ptraceptrace-peekdata

