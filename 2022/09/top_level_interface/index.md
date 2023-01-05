# angr文档翻译（二）Top Level Interface


# Top Level Interface

## 开始之前（Before You Start）

我们预期的angr主要的应用场景是Ipython（或者其他python命令行解释器）。当你不确定可以用什么接口时，tab键的 补全往往能帮助到你。

有时Ipython中的tab补全会很慢。我们发现以下解决方法很有效且不会影响补全功能的完整性：

```python
# 将此文件放在Ipython配置文件的启动目录中可以避免每次都单独1运行它
import IPython
py = IPython.get_ipython()
py.Completer.use_jedi = False
```

## 核心概念（Core Concepts）

在开始使用angr之前，你将会对angr的基本概念和如何构造一个angr对象有一个基本的概览。我们将通过二进制程序加载后直接可用的接口来说明这些概念。

你使用angr做的第一件事往往是把二进制程序加载到工程中，我们以`/bin/true`为例

```python
>>> import angr
>>> proj = angr.Project('/bin/true')
```

在angr中，一个project是你所能控制的基本单元，通过project，你将能对刚刚加载的二进制程序进行分析和模拟。几乎你在angr项目中使用的每一个对象都依赖于某种形式的project而存在

### 基本属性（Basic properties）

首先，project有一些基本属性：它的CPU架构，它的文件名和程序入口点。

```python
>>> import monkeyhex # 用来将数字结果转化为16进制
>>> proj.arch
<Arch AMD64(LE)>
>>> proj.entry
0x401670
>>> proj.filename
'/bin/true'
```

- `arch`是`archinfo.Arch`对象的实例，用来指明程序编译的架构，在这个例子中是little-endian amd64。它包含许多它所运行的CPU的信息，你可以在闲暇时细读。通常情况下你所关心的是`arch.bits`，`arch.bytes`（这个是main Arch class 的@property声明），`arch.name`和`arch.memory_endness`

- `entrry`是二进制程序的入口点

- `filename`显然是二进制程序的文件名

### 加载器（The loader）

从一个二进制程序到它在虚拟地址空间的映射是十分复杂的！我们有一个叫`CLE`(Christophe's Loader for Everything) 的模块去解决这个问题。CLE就是一种加载器，可以通过`.loader`属性调用。我们将在后面详细了解如何使用它，但现在你只需知道你可以用它查看angr随着你的程序加载的动态链接库（shared libraries）并且执行一些对于他们地址空间的基本的查询

```python
>>> proj.loader
<loaded true, maps [0x400000:0x5004000]>

>>> proj.loader.shared_objects # 或许和你的看起来有点不一样
{'ld-linux-x86-64.so.2': <ELF Object ld-2.24.so, maps [0x2000000:0x2227167]>,
 'libc.so.6': <ELF Object libc-2.24.so, maps [0x1000000:0x13c699f]>}

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5004000

>>> proj.loader.main_object # 我们已经在项目中加载了几个二进制程序。这里是主要的一个
<ELF Object true, maps [0x400000:0x60721f]>

>>> proj.loader.main_object.execstack # 查询示例：是否存在可执行栈段
False
>>> proj.loader.main_object.pic # 查询示例：这个二进制程序是地址无关代码吗？
# pic(position-independent code)指可在主存储器中任意位置正确执行，而不受其绝对地址影响的一种机器码，常用于动态链接库
```

### 工厂（The Factory）

在angr中有许多类，而它们中的大多数需要一个project去把他们实例化。我们并不会让你到处传递project，而是提供了`project.factory`，其中包含了一些你会频繁使用到的、常见对象的构造器。

本节还将介绍angr的一些基本概念。

#### 块（Blocks）

首先，我们有`project.factory.block()`，常常用来从给定地址提取基本代码块。这是一个重要的事实——angr以块为基本单位分析代码。你会得到一个block对象，其中包含了许多关于这个代码块的有趣的东西

```python
>>> block = proj.factory.block(proj.entry) # 从程序的入口点取出一个代码块
<Block for 0x401670, 42 bytes>

>>> block.pp() # pretty-print 向stdout输出相应反汇编代码
0x401670:       xor     ebp, ebp
0x401672:       mov     r9, rdx
0x401675:       pop     rsi
0x401676:       mov     rdx, rsp
0x401679:       and     rsp, 0xfffffffffffffff0
0x40167d:       push    rax
0x40167e:       push    rsp
0x40167f:       lea     r8, [rip + 0x2e2a]
0x401686:       lea     rcx, [rip + 0x2db3]
0x40168d:       lea     rdi, [rip - 0xd4]
0x401694:       call    qword ptr [rip + 0x205866]

>>> block.instructions # 在这个代码块中共有多少条指令？
0xb

>>> block.instruction_addrs # 这个代码块中指令的地址分别是多少？
[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]
```

更多的，你可以使用block对象获得块代码的其他表示形式

```python
>>> block.capstone                       # capstone disassembly
<CapstoneBlock for 0x401670>
>>> block.vex                            # VEX IRSB (这是python内部地址，而不是程序内部地址)
<pyvex.block.IRSB at 0x7706330>
```

#### 状态（states）

关于angr的另一个事实是——project对象仅仅相当于程序的一个“初始化镜像”。当你使用angr执行运行程序时，你正在使用一个模拟程序运行状态的对象-`SimState`。比如：

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

一个SimState记录着一个程序的内存、寄存器、文件信息...任何可以通过程序执行更改的“实时数据”健康都会被存储进去。稍后我们将会介绍如何与这些状态交互，但是现在，让我们用`state.regs`和`state.mem`来查看当前状态下的寄存器和内存

```python
>>> state.regs.rip # 取得当前指令的地址
<BV64 0x401670>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.etry].int.resolved # 将入口点的内存以C语言中int类型显示
<BV32 0x8949ed31>
```

这些并不是python的ints！这些是`bitvectors`。python中的integers与CPU层面的字（words）并不是一个概念，例如python不会产生整数溢出。所以我们使用`bitvectors`，可以将其视为一串bits构成的整数，angr中用它来代表CPU data。注意每个bitvector都有一个`.length`属性来描述它是多少bits宽

我们在后面将会学习如何使用它们，但是现在，我们列出了如何将数字在python int和bitvector之间转换的方法

```python
>>> bv = state.solver.BVV(0x1234, 32) # 创建一个32bit宽的bitvector,它的值是0x1234 
<BV32 0x1234>                     # BVV：bitvector value
>>> state.solver.eval(bv)    # 将bitvector转化为python int
0
```

你可以把bitvector存回寄存器和内存，或者直接存储python integer类型值，它会被自动转化成合适大小的bitvector

```python
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>

>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

`mem`接口刚开始看令人困惑，因为它使用了一些强大的python魔法，下面是简要的使用指南：

- 使用`array[index]`来指明确定的地址

- 用`.<type>`来指定内存数据的类型（常用类型：char, short, int, long, size_t, uint8_t, uint16_t...)

- 通过mem接口你可以：
  
  - 存储一个值到内存，既可以是bitvector,也可以是python int
  
  - 用`.resolve`来获取内存值并转化为bitvector
  
  - 用`.concrete`来获取内存值并转化为python int

还有更多高级用法将在后面提到

最终，如果你尝试读取更多寄存器的值，你可能会遇到一个长得十分奇怪的值

```python
>>> state.regs.rdi
<BV64 reg_48_11_64{UNINITIALIZED}>
```

这同样是一个64位bitvector，但是它并没有携带数值，相反的，它有一个名字！它被称为符号变量，也是符号执行的基础。不要恐慌！我们会在两章之后讨论它的细节

#### 模拟管理器（Simulation Managers）

如果程序在任意给定的时间点都有一个状态，那么必然有一种方法可以让它变成下一种状态。`simulation manager`是angr执行中的主要接口。模拟（simulation）无论你如何叫它，它都是带有状态的。作为一个简短的介绍，让我们看看如何在我们之前创建的代码块中标记状态。

首先，我们要创建一个simulation manager，构造函数可以传入一个状态或状态列表

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
>>> simgr.active
[<SimState @ 0x401670>]
```

一个simulation manager可以有多种状态的封装（stash），默认的stash是`active`，用我们传入的状态初始化。如果还不够的话，我们可以查看`simgr.active[0]`来进一步了解各种状态

现在， 准备好，我们要进行一些程序的执行了。

```python
>>> simgr.step()
```

我们刚刚进行了一个基本快的符号执行！

我们可以再看看active stash，注意它已经被更新了，并且它并没有改变我们原来的状态。SimState对象在执行时被视为不可变，所以你可以安全地将单个状态作为多轮执行的开始（base）

```python
>>> simgr.active
[<SimState @ 0x1020300>]
>>> simgr.active[0].regs.rip                 # new and exciting!
<BV64 0x1020300>
>>> state.regs.rip                           # still the same!
<BV64 0x401670>
```

/bin/true不是一个很好的例子来描述如何用符号执行做有趣的事，所以我们现在就到此为止

### 分析（Analyse）

angr预先打包了一些内置分析方法，你可以利用它们从程序中提取一些有趣的信息。

```python
>>> proj.analyses.            # 在这里按tab来列出所有内置的分析方法
 proj.analyses.BackwardSlice        proj.analyses.CongruencyCheck      proj.analyses.reload_analyses       
 proj.analyses.BinaryOptimizer      proj.analyses.DDG                  proj.analyses.StaticHooker          
 proj.analyses.BinDiff              proj.analyses.DFG                  proj.analyses.VariableRecovery      
 proj.analyses.BoyScout             proj.analyses.Disassembly          proj.analyses.VariableRecoveryFast  
 proj.analyses.CDG                  proj.analyses.GirlScout            proj.analyses.Veritesting           
 proj.analyses.CFG                  proj.analyses.Identifier           proj.analyses.VFG                   
 proj.analyses.CFGEmulated          proj.analyses.LoopFinder           proj.analyses.VSA_DDG               
 proj.analyses.CFGFast              proj.analyses.Reassembler
```

本手册后面会记录其中的一些方法，但总的来说，如果你想要找到如何使用内置的分析方法，你应该查看[api文档](https://api.angr.io/angr)。作为一个简短的例子：下面说明了你应该怎样生成并使用一个快速的程序控制流图：

```python
# 刚开始时，当我们加载二进制文件时，它还将其所有依赖项加载到同一块虚拟内存中
# 这对于大多数分析是不愿意看到的
>>> proj = angr.Project('/bin/true', auto_load_libs=False)
>>> cfg = proj.analyses.CFGFast()
<CFGFast Analysis Result at 0x2d85130>

# cfg.graph 是一个充满了CFGNode实例的 networkx DiGraph 
# 你应该去看 networkx APIs 的文档去学习如何使用它
>>> cfg.graph
<networkx.classes.digraph.DiGraph at 0x2da43a0>
>>> len(cfg.graph.nodes())
951

# 去获取指定地址的 CFGNode， 可以用 cfg.get_any_node
>>> entry_node = cfg.get_any_node(proj.entry)
>>> len(list(cfg.graph.successors(entry_node)))
2
```

### Now what？

阅读完这一页之后，你应该熟悉了angr几个重要概念：basic blocks, states, bitvectors, simulation managers 和analyses。但是除了把angr作为美化的调试器以外，你还不能做任何事情。继续阅读，你将解锁更深层次的力量...

