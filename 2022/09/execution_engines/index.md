# angr文档翻译（七）Execution Engines


# Execution Engines

当你使用angr进行单步执行时，某些东西实际地进行了执行，即angr的一系列引擎（SimEngine的子类），它们会模拟给定代码段对输入状态的影响。angr的执行内核只是依次尝试所有可用的引擎，使用第一个可以处理该步骤的引擎。默认的引擎列表，按顺序排列如下：

- 故障引擎（failuer engine）：当某一步导致一个无法继续的状态时，故障引擎启动。

- 系统调用引擎（syscall engine）：当某一部产生系统调用时，系统调用引擎启动。

- hook引擎（hook engine）：当当前地址被hook时启动

- unicorn引擎（unicorn engine）：当`UNICORN`状态选项开启并且状态中无符号数据时unicorn引擎启动

- VEX引擎（VEX engine）：VEX引擎是最终后备引擎

## 模拟后继（SimSuccessors）

实际上依次尝试所有可用引擎的函数是`project.factory.successprs(state, **kwargs)`，它将参数传递给每个引擎。这个函数是`state.step()`和`simulation_manager.step()`的核心，它返回一个SimSuccessors对象。设计SimSuccessors的目的是对存储在各种列表属性中的后继状态进行简单分类，如下：

| 类别（Attribute）            | 警戒条件（Guard Condition）    | 命令指针（Instruction Pointer）                            | 描述（Description）                                                                                                                                                                                                                                                                                                                                 |
| ------------------------ | ------------------------ | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| successors               | True（可以被符号化，但被限制为True）   | 可以被符号化（但最多有256个solution）参阅`unconstrained_successors` | 引擎处理正常可满足的状态，该状态的指令指针可能是符号化的（根据用户输入进行跳转），所以这个状态可能代表了几个潜在的后继状态                                                                                                                                                                                                                                                                                   |
| unsat_successors         | False（可以被符号化，但被限制为False） | 可以被符号化                                               | 不可满足的后继状态，它的Guard Condition只能为Flase（即不能进行跳转或必须进行默认分支跳转）                                                                                                                                                                                                                                                                                         |
| flat_successors          | True（可以被符号化，但被限制为True）   | 具体的值                                                 | 如上所述，后继列表中的状态可以具有符号指令指针。这个理解起来十分复杂，和在其他地方的代码（例如SimEngineVEX.process当其中状态向前执行时），我们假设单个状态仅代表代码中单个点的执行。为了便于理解，当我们遇到带有符号指令指针的后继状态时我们为它们计算所有可能的solution，并为每一个这样的solution制作一份状态拷贝，我们称这个过程为扁平化。这些flat_successors是一些状态，它们每个状态都带有一个不同的具体值的指令指针。举个例子，如果后继状态的指令指针是X+5，而X有X>0x800000和X<=0x800010的约束。我们会将其展平为16个不同的flat_successors状态，指令指针从0x800006一直到0x80015 |
| unconstrained_successors | True（可以被符号化，但被限制为True）   | 符号化（超过256个solution）                                  | 在上述的扁平化过程中，如果指令指针有超过256种可能的solution，我们就假设该指令地址已被无约束数据覆盖（例如用户数据的栈溢出），这个情况一般是不合理的，这些状态被放在unconstrained_successors中，而不是后继状态中                                                                                                                                                                                                                       |
| all_successors           | anything                 | 可以被符号化                                               | 上述三个successors的集合                                                                                                                                                                                                                                                                                                                               |

## 断点（Breakpoints）

TODO: rewrite this to fix the narrative

和任何一个不错的执行引擎一样，angr支持设置断点。这很酷！你可以像下面这样设置断点：

```python
>>> import angr
>>> b = angr.Project('examples/fauxware/fauxware')

>>> s = b.factory.entry_state()

# 添加一个断点，在发生内存写入之前放入ipdb
>>> s.inspect.b('mem_write')

# 或者，我们可以在内存写入发生之后立即触发断点
# 我们也可以运行一个回调函数而不是打开ipdb
>>> def debug_func(state):
        print("State %s is about to do a memory write!")
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=debug_func)

# 或者，你可以把它放到你的ipython中
>>> s.inspect.b('mem_write', when=angr.BP_AFTER, action=angr.BP_IPYTHON)
```

除了内存写入之外，还有其他很多地方可以设置断点。下面展示的是个可设置断点的事件列表，你都可以把他们设置为`BP_BEFORE`或`BP_AFTER`

| Event type             | Event meaning                     |
| ---------------------- | --------------------------------- |
| mem_read               | 内存被读取时                            |
| mem_write              | 内存被写入时                            |
| address_concretization | 正在解析符号化内存访问                       |
| reg_read               | 一个寄存器被读取时                         |
| reg_write              | 一个寄存器被写入时                         |
| tmp_read               | 一个临时变量被读取时                        |
| tmp_write              | 一个临时变量被写入时                        |
| expr                   | 正在创建表达式（即获得算术运算的结果或IR中的常数）        |
| statement              | 正在翻译一个IR声明（statement）             |
| instruction            | 正在翻译一条新的（本机）指令                    |
| irsb                   | 正在翻译一个基本块                         |
| constraints            | 新的约束被添加到state中                    |
| exit                   | 正在从执行中生成后继状态                      |
| fork                   | 一个符号执行状态分叉成多个状态                   |
| symbolic_variable      | 正在创建一个新的符号变量                      |
| call                   | 正在执行call指令                        |
| return                 | 正在执行ret指令                         |
| simprocedure           | 正在执行simprocedure（或syscall）        |
| dirty                  | 正在执行dirty IR callback             |
| syscall                | syscall被执行（除了simprocedure事件之外的调用） |
| engine_process         | SimEngine即将处理一些代码                 |

这些事件拥有不同的属性：

（表格太长不搬了）链接：https://docs.angr.io/core-concepts/simulation

这些属性可以在适当的断点回调期间作为`state.inspect`的成员访问，以获取适当的值。你甚至可以修改这些值来为你所用

```python
>>> def track_reads(state):
...     print('Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address)
...
>>> s.inspect.b('mem_read', when=angr.BP_AFTER, action=track_reads)
```

此外，这些属性都可以作为`inspect.b`的参数，使断点被条件约束：

```python
# 如果0x1000是目标表达式的可能值，则将会在内存写入之前触发断点
>>> s.inspect.b('mem_write', mem_write_address=0x1000)

# 如果0x1000是目标表达式的唯一可能值，则将在内存写入之前触发断点
>>> s.inspect.b('mem_write', mem_write_address=0x1000, mem_write_address_unique=True)

# 若0x1000是从内存中读取的最后一个表达式的可能值，则会在0x8000指令之后触发断点
>>> s.inspect.b('instruction', when=angr.BP_AFTER, instruction=0x8000, mem_read_expr=0x1000)
```

事实上，我们甚至可以指定一个函数作为条件

```python
# 这是一个复杂条件，它确保RAX为0x41414141并且从0x8004开始的基本块在此路径之前的某个时间执行
>>> def cond(state):
...     return state.eval(state.regs.rax, cast_to=str) == 'AAAA' and 0x8004 in state.inspect.backtrace

>>> s.inspect.b('mem_write', condition=cond)
```

## 关于使用mem_read断点的注意事项

每当程序读取内存时，就会触发`mem_read`断点。如果在设置这种断点的同时还使用`state.mem`从内存地址加载数据，那么断点也将被触发

因此，如果你想从内存中加载数据而不触发`mem_read`断点，请使用`state.memory.load`携带关键词参数`disabl_actions=True`和`inspect=False`

对于`state.find`方法也同上

