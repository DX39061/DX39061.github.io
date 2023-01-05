# angr文档翻译（六）Simulation Managers


# Simulation Managers

Simulation Manager是angr中最重要的控制模块，它让你能够控制不同状态的符号执行，使用搜索策略来探索程序的状态空间。在这一节中，你将学会如何使用它。

Simulation Manager让你以一种巧妙的方式处理多个状态。多种状态组成“存储区（stashes）”，你可以任意前进、过滤、合并和移动。例如，你可以以不同速率步进两个不同的存储区，然后将它们合并在一起。大多数操作的默认存储区是`active`存储区，当你初始化simlation manager时，状态就放在里面。

## 单步执行（Stepping）

simulation manager最基础的功能是通过`.step()`将默认存储区的所有状态向前推进一个基本块。

```python
>>> import angr
>>> proj = angr.Project('examples/fauxware/fauxware', auto_load_libs=False)
>>> state = proj.factory.entry_state()
>>> simgr = proj.factory.simgr(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
>>> simgr.active
[<SimState @ 0x400540>]
```

当然，存储区模型真正的威力在于，当一个状态遇到符号分支条件时，两个后继状态都会出现在存储区中，然后你可以同步执行两个分支。当你并不关心程序控制流只想单步执行到结束时，可以使用`.run()`方法

```python
# 运行直到第一个符号分支
>>> while len(simgr.active) == 1:
...    simgr.step()

>>> simgr
<SimulationManager with 2 active>
>>> simgr.active
[<SimState @ 0x400692>, <SimState @ 0x400699>]

# 运行直到程序退出
>>> simgr.run()
>>> simgr
<SimulationManager with 3 deadended>
```

我们现在有3个挂掉的状态！当一个状态在执行过程中没有产生任何后继状态时，例如，程序执行到了exit系统调用，这个状态就会被从`active`存储区移除放到`deadended`存储区中

## 存储区管理（Stash Management）

让我们看看如何使用其他存储区。

要在存储区之间移动一个状态，可以使用`.move()`方法，参数为`from_stash``to_stash`和`filter_func`（可选的，默认是移动一切）。例如，我们可以移动输出中包含热指定字符串的state：

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```

我们在移动指定state的同时，创建了一个叫“authenticated”的存储区。存储区中每个state在其标准输出中都有“Welcome”，这是一个很好的做法。

每个存储区都只是一个列表，你可以使用下表索引或迭代访问每个单独的state，但是也有一些方法可以替代使用。如果你在存储区名前加一个`one_`前缀，你将得到存储区中的第一个state。如果你在存储区名前加一个`mp_`前缀，你将得到该存储区的[mulpyplexed](https://github.com/zardus/mulpyplexer)版本

```python
>>> for s in simgr.deadended + simgr.authenticated:
...     print(hex(s.addr))
0x1000030
0x1000078
0x1000078

>>> simgr.one_deadended
<SimState @ 0x1000030>
>>> simgr.mp_authenticated
MP([<SimState @ 0x1000078>, <SimState @ 0x1000078>])
>>> simgr.mp_authenticated.posix.dumps(0)
MP(['\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00',
    '\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x80\x80\x80\x80@\x80@\x00'])
```

当然，`step``run`和其他操作单个存储区的方法都可以携带一个`stash`参数，指明是对那个存储区操作

simulation manager为你提供了许多有趣的工具来管理存储区。我们暂时不会讨论其他内容，你可以查看API文档了解细节。

## 存储区类型（Stash types）

你可以任意使用存储区，但有一些存储区被用来对某些特殊类型的状态进行分类。

- `active`：此存储器包含默认情况下使用`step`方法会被执行的state，除非特别指定了存储区

- `deadended`：当一个state由于某种原因不能继续执行时，它会进入`deadended`存储区，包括没有更多有效指令，所有后继状态无解和无效的指令指针。

- `pruned`：当使用`LAZY_SOLVES`时，非必要不会检查状态是否满足。当在`LAZY_SOLVES`存在时约束条件不满足时，state会遍历层次结构，找到最初不满足的state，该状态的所有后继状态都会被剪除并放入此存储区中

- `unconstrained`：当Simulation Manager的构造函数被指定`save_unconstrained`选项时，则将被确定为不受约束的state放在此存储区

- `unsat`：当Simulation Manager的构造函数被指定`save_unsat`选项时，则将被确定为不满足约束（有矛盾约束）的state放在此存储区

还有一个不是存储区的state列表：`errored`，如果在符号执行期间发生错误，则state将被包装在`ErrorRecord`对象中，其中包含state和它引发的错误信息，然后这条记录将被插入到errored中。你可以通过`record.state`获取错误发生之前的状态，通过`record.error`得到引发的错误，并且你可以通过`record.debug()`在引发错误的位置启动调试shell，这是一个非常宝贵的调试工具！

## 简单的符号执行探索（Simple Exploration）

运用符号执行的一个常见的目的是得到程序运行到特定地址时的状态，同时丢弃通过另一个地址的所有状态，simulation manager有这个模式的快捷方法，可以使用`explore()`方法

当使用`.explore()`方法并携带`find`参数时，符号执行将一直进行直到得到与查找条件匹配的状态，find参数可以是某个地址，也可以是某些地址组成的列表，还可以是接受`state`参数返回是否成功的断言的函数。当`active`存储区中的任何状态与`find`的条件匹配时，这些state会被放进`found`存储区，并且中止符号执行。之后你可以继续符号执行探索found存储区中的状态，或者丢弃这些状态并继续其他状态。你还可以使用`avoid`指定与find相同的条件参数，当一个状态符合avoid条件时，它会被放进avoid存储区中，并继续执行。最终，`num_find`参数控制在angr结束之前应该找到的状态数，默认值为1。当然，如果你在找到足够数量满足条件的状态之前用完了active存储区中所有的状态，则无论如何都会停止执行。

我们以crackme程序为例

首先，我们要加载这个二进制程序

```python
>>> proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
```

下一步，创建Simulation Manager

```python
>>> simgr = proj.factory.simgr()
```

现在，我们进行符号执行直到我们找到一个状态符合我们指定的条件

```python
>>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
```

现在，我们可以从state中得到flag

```python
>>> s = simgr.found[0]
>>> print(s.posix.dumps(1))
Enter password: Congrats!

>>> flag = s.posix.dumps(0)
>>> print(flag)
g00dJ0B!
```

十分简单，不是吗？

## 探索技术（Expolration Techniques）

angr附带了几个固定功能，可以让你自定义Simulation Manager的行为，这些功能叫做`expolration techniques`。至于为什么要使用探索技术，一个典型的例子是可以修改探索程序状态空间的模式，默认“一次执行所有操作”策略实际上是广度优先搜索，但是通过探索技术，你可以实现深度优先搜索。这些技术的能力远比这个例子更加灵活——你可以完全改变angr执行的行为。编写自己的探索技术将在后面的章节中介绍。

要使用探索技术，请调用`simgr.use_technique(tech)`，其中tech是EXploration Technique子类的一个实例。angr内置的探索技术可以在`angr.exploration_techniques`找到

下面是一些内置技术的概览：

- `DFS`：深度优先搜索，`active`存储区只存放一个state，其他state被放入`deferred`存储区直到`active`存储区的state终止或产生错误

- `Explorer`：这个技术实现了`.explore()`方法，可以指定`explore`和`avoid`

- `LengthLimiter`：限制状态通过路径的最大长度

- `LoopSeer`：使用循环计数的合理近似值来暂时丢弃通过循环次数过多的状态，将他们放入`spinning`存储区，如果其他可行的状态被用完，则重新将他们拉出使用

- `ManualMergepoint`：将程序中一个地址标记为合并点，到达该地址的状态将被暂时保存，并且在超时时间内到达同一点的其他状态都将被合并在一起。

- `MemoryWatcher`：监控simgr执行过程中系统内存空闲，如果变得太低，则停止执行

- `Oppologist`：“operation apologist”是一个特别有趣的小工具——如果启用此技术并且angr遇到不受支持的指令，例如，一个奇怪的外来浮点SIMD操作，它会将所有输入具体化并使用unicorn引擎模拟单个指令，从而允许继续执行

- `Spiller`：当`active`存储区状态过多时，此技术可以将其中一些状态转存到磁盘以保持较低的内存消耗

- `Threading`：将线程级并行性添加到执行过程。由于python的全局解释器锁，这并没有多大帮助，但是如果你有一个程序的分析花费大量时间在angr的本机代码依赖项（unicorn、z3、libvex）中，你可能会获得一些收益

- `Tracer`：一种探索技术，它使符号执行遵循从其他来源记录的动态跟踪。动态跟踪器[存储库](https://github.com/angr/tracer)有一些工具可以生成这些跟踪

- `Veritesting`：关于自动识别有用合并点的[CMU论文](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf)的实现，它十分有用，你可以在构造Simulation Manager时使用`veritesting=True`参数来开启这个技术！请注意，由于它实现的是静态符号执行的侵入性方式，它通常不能与其他技术配合使用。

查看[Simulation Manager](http://angr.io/api-doc/angr.html#module-angr.manager)和[探索技术](http://angr.io/api-doc/angr.html#angr.exploration_techniques.ExplorationTechnique)的API文档以获取更多信息

