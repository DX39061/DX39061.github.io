# “字”的歧义--深入ptrace返回值类型


## 众说纷纭

最近在学ptrace的各种用法，看到使用`PTRRACE_PEEKDATA`读取数据时产生了疑惑

ptrace函数签名：

```c
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

大量文章中写道:

> PTRRACE_PEEKDATA从内存地址中读取一个字节，内存地址由addr给出

重点在于**读取一个字节**，但奇怪的是ptrace函数返回值却是long类型

少部分文章中改成了**读取四个字节**，估计是注意到了long类型返回值

又去查了查[ptrace文档](https://man7.org/linux/man-pages/man2/ptrace.2.html)，上面这么描述：

> Read a word at the address *addr* in the tracee's memory, returning the word as the result of the **ptrace**() call.

怎么又变成了一个字（word），两个字节？

## 柳暗花明

最终发现了stackoverflow的一篇[文章](https://stackoverflow.com/questions/20974068/does-the-size-of-a-long-equal-to-the-size-of-a-word)，其中提到ptrace文档中的一个note（小小吐槽一下，这个note在整篇文章的末尾，前文也没什么标注，不专门去找很难看到

> The size of a "word" is determined by the operating-system variant (e.g., for 32-bit Linux it is 32 bits).

由此终于清楚，这里所说的word由操作系统位数决定，32位系统上是32位，64位系统上是64位

## “字”的歧义

作为天天跟汇编打交道的逆向壬，我先入为主的认为一个word就是2字节，却忘了word的定义：

> A *word is the amount of data that a machine can process at one time*.

之所以在汇编以及许多场合中把字（word）规定为2字节（2 bytes），大概是为了更统一、更准确地描述数据大小，并且出现了双字、四字之类的东西

但仍有很多情况下，仍使用“字”的原始定义，与系统一次能处理的最大数据量相对应，long这种C语言数据结构的大小即是一个“字”

