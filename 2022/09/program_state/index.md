# angr文档翻译（五）Program State


# Program State

到目前为止，我们只使用了angr的程序状态模拟（`SimState` objects），以最简单的方式展示了有关angr的基本操作。这一节中，你将了解state对象的结构以及如何与state交互。

## 回顾：读写内存和寄存器（Review: Reading and writing memory and registers）

如果你按顺序读了该文档之前的内容（你也应该这样做，至少应该按顺序读完第一部分），你已经了解了访问内存和寄存器的基本操作，`state.regs`接受寄存器名称作为参数可以对寄存器进行读写，`state.mem`可以用地址作为索引获取相应地址的值，索引后可以指定数据类型。

以下是一些示例：

```python
>>> import angr, claripy
>>> proj = angr.Project('/bin/true')
>>> state = proj.factory.entry_state()

# 把rsp的值复制到rbp
>>> state.regs.rbp = state.regs.rsp

# 把rdx的值存到地址为0x1000内存中
>>> state.mem[0x1000].uint64_t = state.regs.rdx

# 改变rbp所指向的地址
>>> state.regs.rbp = state.mem[state.regs.rbp].uint64_t.resolved

# add rax, qword ptr [rsp + 8]
>>> state.regs.rax += state.mem[state.regs.rsp + 8].uint64_t.resolved
```

## 基础执行（Basic Execution）

早些时候，我们展示了如何使用Simulation Manager来进行一些基本的执行。我们将在下一节展示Simulation Manager的全部功能，但我们现在可以使用一种各简单的接口`state.step()`来演示符号执行的工作原理。这个接口会进行一步符号执行，并返回一个`SimSuccessors`对象。与一般的模拟执行相比，符号执行可以产生多个可以按多种方式分类的后继状态。现在，我们关心的是这个对象的`.successors`属性，它会返回一个包含给定步骤的所有“正常”后续状态的列表。

为什么返回的是一个列表，而不是一个唯一的后继状态？angr的符号执行过程只是将单个指令的操作编译到程序中并执行它们以改变SimState。当遇到像`if(x>4)`这样的代码时，如果x是符号变量会发生什么呢？在angr的底层某个地方，会处理`x>4`语句，结果将是`<Bool x_32_1 > 4>`

这很好，但下一个问题是，我们是选择“true”分支还是“false”分支？答案是：两个分支都会被执行，产生两个完全独立的后继状态。在第一个state中，我们添加`x>4`作为约束条件，在第二个state中，我们添加`!(x>4)`作为约束条件。每当我们使用这些后继状态中的任何一个进行约束求解时，状态的条件确保我们得到的任何有效值都是有效的输入，这将导致重复执行遵循给定状态的路径

为了证明这一点，让我们以`fake firmware images`为例，如果你查看这个二进制文件的源代码，你会发现固件的身份验证机制是存在后门的：任何用户名都可以通过密码“SOSNEAKY”获得管理员权限。更进一步来说，与用户输入的比较就是存在后门的，所以如果我们单步执行进行比较，获得多个后继状态。其中一种状态将包含将用户输入限制为后门密码的条件。以下代码片段实现了这一点：

```python
>>> proj = angr.Project('examples/fauxware/fauxware')
>>> state = proj.factory.entry_state(stdin=angr.SimFile)  # 目前请忽略这个配置，为了教学，我们禁用了更复杂的默认配置
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1, state2 = succ.successors
>>> state1
<SimState @ 0x400629>
>>> state2
<SimState @ 0x400699
```

不要直接去看这些状态的约束——我们刚经过的分支涉及到`strcmp`的结果，这是一个难以用符号方式模拟的函数，由此产生的约束非常复杂。

我们模拟的程序从标准输入获取数据，默认情况下将其视为无限的符号数据流。为了进行约束求解，我们需要stdin实际内容的引用，我们稍后将会讨论我们的文件和输入子系统是如何工作的，但现在，只需使用`state.posix.stdin.load(0, state.posix.stdin.size)`取得到目前为止从标准输入读取的所有内容构成的bitvector。

```python
>>> input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)

>>> state1.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00\x00\x00'

>>> state2.solver.eval(input_data, cast_to=bytes)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00\x00\x00'
```

正如你所见，为了进入`state1`路径，你必须将后门字符串“SOSNEAKY”作为密码，为了进入`state2`路径，你必须输入后门字符串以外的内容。z3打印了数十亿个符合的字符串之一。

Fauxware是第一个angr成功进行符号执行的程序，时间在2013年。通过使用angr找到它的后门，你正在参与一个伟大的传统，你已经对如何通过符号执行从二进制程序中获取有意义信息有了基本的了解！

## 预设状态（State Presets）

在此之前，当我们操作state时，都会使用`project.factory.entry_state()`来创建一个新的状态，这只是angr可使用的几个构造函数之一：

- `.blank_state()`构造一个空白状态，它的大部分数据都未初始化，访问未初始化的数据时，会得到一个不带约束的符号值

- `.entry_state()`构造一个在main函数入口点的状态

- `.full_init_state()`构造一个准备好在main函数入口点之前运行的初始化程序执行。例如：共享库构造函数或预设初始化器，完成这些后，它将跳转到程序入口点

- `.call_state()`构造一个准备好执行给定函数的状态

你可以通过以下构造函数参数自定义状态

- 上述所有构造函数都可以使用`addr`参数指定开始执行的确切地址

- 如果你在符号执行过程中需要命令行参数或环境变量，可以使用`args`列表或`env`字典传递参数，只有`entry_state`和`full_init_state`可使用。这些参数中的值可以是字符串或bitvector，都会被序列化为state中的args和env。默认的args是个空列表，所以哪怕你的程序只需要`argv[0]`，你都需要自己提供

- 如果你需要使用符号化的`argc`，你可以将一个bitvector传递给`argc`参数，只有`entry_state`和`full_init_state`可使用。但是要小心，如果你这样做，你要添加一个约束：argc的值不能大于args的数量

- 要使用call state，你应该使用`.call_state(addr, arg1, arg2, ……)`，addr是你要调用的函数的地址，`argN`是该函数的第n个参数，无论是python 整数、字符串、列表还是bitvector都可以。如果你想得到内存中指向一个对象的实际的指针，你应该将其包装在`PointerWrapper`中，即`angr.PointerWrapper("point to me!")`，这个API结果可能存在问题，我们正在努力改善

- 使用`call_state`时若要指定函数的调用约定，可以使用`cc`参数传递一个`SimCC实例`。一般情况下angr会选择一个合适的方式作为默认值，但在特殊情况下，需要你手动指定

在这些构造函数中还有更多的选项可以使用，更多详细信息，请参阅[docs on the project.factory object (an AngrObjectFactory)](https://api.angr.io/angr)

## 内存底层接口（Low level interface for memory）

`state.mem`接口便于从内存中加载特定类型的数据，但是当你想要对一段内存进行原样的加载和存储时，它就显的十分繁琐。事实上，`state.mem`的底层使用了`state.memory`，`state.memory`表示一个填充了bitvector的平坦地址空间。你可以使用`state.memory.load(addr, size)`和`state.memory.store(addr, val)`直接操作内存：

```python
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # 加载大小以字节为单位
<BV48 0x89abcdef0123>
```

正如你所见，数据以大端序进行加载和存储，因为`state.memory`的主要目的是加载没有附加语义的存储数据。但是，如果你想把它们转化为小端序，你可以设置`endness`为little-endian。endness的取值应该是`archinfo`包中`Endness`枚举量之一。此外，正在分析程序的字节序可以从`arch.memory_endness`得到，例如`state.arch.memory_endness`

```python
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67452301>
```

还有一个用于寄存器访问的底层接口`state.registers`，使用方法与`state.memory`完全相同，但解释它的行为需要深入了解angr用于无缝处理多架构的抽象。简单来说它是一个寄存器文件，寄存器和偏移量的映射在[archinfo](https://github.com/angr/archinfo)中定义

## 状态选项（State Options）

你可以使用一些状态选项对angr的内部进行很多小调整，这些调整在某些情况下会优化angr的行为，而在其他情况下会有所损害。

在每个SimState对象上，都有一组启用的选项（state.options）。每个选项（实际上只是一个字符串）都以某种微小的方式控制angr执行引擎的行为。可以在附录中找到完整的[选项列表](https://docs.angr.io/appendix/options)及其默认值。你可以使用`angr.options`访问并向state添加某个选项。单个选项一般以大写字母命名，但也有一些你可能希望捆绑在一起使用的常用对象分组，以小写字母命名。

无论用任何构造函数创建SimState时，你都可以使用参数`add_options`和`remove_options`传递从默认值修改的选项。

```python
# 例如: 启用lazy_solves, 这个选项会尽可能减少检查状态是否满足约束
# 对此设置的更改会影响此行之后所有由此状态创建的后继状态
>>> s.options.add(angr.options.LAZY_SOLVES)

# 创建一个state并且开启lazy_solves
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})

# 创建一个不启用simplification选项的新状态
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```

## 状态插件（State Plugins）

除了刚刚讨论的各种选项之外，存储在SimState中的所有内容实际上都存储在附加到state的各种插件中。到目前为止，我们讨论的几乎每个state属性（memory、registers、mem、regs、solver等等）都是可插拔的。这种设计允许代码模块化，以及模拟状态的其他方面轻松实现新型数据存储，或者使用其他插件替代实现。

例如，普通的`memory`插件模拟了一个平坦的内存空间，但是分析时可以选择“abstract memory”插件，它使用地址的替代数据类型来模拟独立于地址的自由浮动内存映射，来提供`state.memory`。另一方面，插件可以降低代码复杂度：`state.memory`和`state.registers`实际上是同一个插件的两个不同实例，因为寄存器也是用地址空间模拟的。

## 全局插件（The global plugin）

`state.globals`是一个非常简单的插件：它实现了python dict相关的接口，允许你在state上存储任意数据。

## 历史插件（The history plugin）

`state.history`是一个非常重要的插件，用于存储符号执行过程中所采用路径的历史数据。它实际上是一些历史节点的链表，每一个节点代表一轮执行，你可以用`state.history.parent.parent……`来遍历这个列表

为了让你更方便地访问历史数据，它还提供了针对某些值好用的迭代器。通常，这些值存储在`history.recent_NAME`，它们的迭代器可以通过`history.NAME`访问。例如，`for addr in state.history.bbl_addrs: print hex(addr)`会打印出经过的二进制基本块的地址，而`state,history.recent_bbl_addrs`是最近一步执行的基本块的列表，`state.history.parent.recent_bbl_addrs`是上一步执行的基本块列表。如果你需要快速访问这些值的平坦（flat）列表，可以使用`.hardcopy`，例如`state.history.bbl_addrs.hardcopy`。但请记住，基于索引的访问是在迭代器上实现的

以下是存储在历史记录中的一些值的简要说明：

- `history.descriptions`是对每一轮执行的字符串描述列表

- `history.bbl_addrs`是执行的基本块地址的列表。每轮执行可能不止一个，并且并非所有地址都对应于二进制代码，有些可能是hook的SimProcedures的地址

- `history.jumpkinds`是历史中每个控制流处理的列表，以VEX枚举字符串形式展现

- `history.jump_guards`是历史中遇到的每个分支的条件列表

- `history.events`是执行期间发生的“有趣事件”的列表，例如符号跳转条件的存在、程序弹出消息框、退出代码终止程序执行

- `history.actions`通常为空，但如果你在state中添加`state.options.refs`，它将记录程序执行时内存、寄存器和临时值被访问的日志

## 调用栈插件（The callstack plugin）

angr会跟踪模拟程序的调用栈过程。在每条调用指令触发时，都会在调用栈的记录顶部添加一个帧（frame），而每当栈指针下降到最顶层帧以下时，就会弹出一个帧。这使angr能稳定地存储当前模拟函数的数据。

和历史记录类似，调用栈记录也是由节点构成的链表，但angr并没有提供对节点内容的迭代器，取而代之的，你可以直接遍历`state.callstack`来获取每个活动帧的调用栈帧，按从最新到最旧排序，如果你想获取顶层帧，那么直接使用`state.callstack`

- `callstack.func_addr`是当前正在执行的函数地址

- `callstack.call_site_addr`是调用当前函数的基本块的地址

- `callsack.stack_ptr`是从当前函数开始的栈指针的值

- `callstack.ret_addr`是当前函数的返回地址

## 更多关于I/O的信息：文件、文件系统、网络套接字（More about I/O: Files, file systems, and network sockets）

请参阅[Working with File System, Sockets, and Pipes](/advanced-topics/file_system)获取详细的文档

## 复制和合并（Copying and Merging）

state支持快速复制，以便你探索不同的分支

```python
>>> proj = angr.Project('/bin/true')
>>> s = proj.factory.blank_state()
>>> s1 = s.copy()
>>> s2 = s.copy()

>>> s1.mem[0x1000].uint32_t = 0x41414141
>>> s2.mem[0x1000].uint32_t = 0x42424242
```

state也可以合并在一起

```python
# 合并会返回一个元组，第一个元素是合并状态
# 第二个元素是描述状态标志的符号变量
# 第三个元素是一个布尔值，描述是否进行过合并
>>> (s_merged, m, anything_merged) = s1.merge(s2)

# 现在这是一个可以解析为“AAAA”或“BBBB”的表达式
>>> aaaa_or_bbbb = s_merged.mem[0x1000].uint32_t
```

TODO：描述合并的限制

