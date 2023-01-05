# angr文档翻译（三）Loading a Binary


# Loading a Binary

在之前的文档中，你仅仅对angr的加载功能进行了一个简单的使用——你加载了`/bin/true`，然后在没有动态连接库的情况下再次加载了它。你也看到了一些angr提供给你的指令比如`proj.factory`。现在，我们将深入这些指令，了解它们之间的差别以及它们能提供给你什么信息。

我们简要的介绍了angr的二进制加载组件CLE（CLE Loads Everything），它常被用来获取二进制程序（以及它的依赖库），并且可以将这些信息以易于使用的形式传递给angr的其他组件

## 加载器（The Loader）

我们以加载`example/fauxware/fauxware`为例，对如何与加载器交互进行一个深入的探究。

```python
>>> import angr, mokeyhex
>>> proj = angr.Project('example/fauxware/fauxware')
>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>
```

## 加载的对象（Loaded Objects）

CLE加载器（cle.loader）是被加载的二进制对象的一个集合，被加载并映射到单独的内存空间。每个二进制对象都可以被相对应的加载器后端加载（cle.Backend的子类）。例如用`cle.ELF`加载ELF文件

在内存中也有与加载的二进制程序无关的对象。比如用来提供线程本地存储支持的对象，用来提供未解析符号的外部对象`externs oobject`。

你可以使用`loader.all_objects`来查看CLE加载的所有对象，还可以通过特定命令查看一些更有针对性的分类

```python
# 所有加载的对象
>>> proj.loader.all_projects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>,
 <ELFTLSObject Object cle##tls, maps [0x3000000:0x3015010]>,
 <ExternObject Object cle##externs, maps [0x4000000:0x4008000]>,
 <KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>]

# 这是main对象，你在加载项目时直接指定的对象
>>> proj.loader.main_object
<ELF Object fauxware, maps [0x400000:0x60105f]>

# 这是动态链接库对象名称和到对象的映射字典
>>> proj.loader.shared_objects
{ 'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
  'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
  'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]> }

# 这是从ELF文件加载的所有对象
# 如果这是windows文件，你可以使用all_pe_objects
>>> proj.loader.all_elf_objects
[<ELF Object fauxware, maps [0x400000:0x60105f]>,
 <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>]

# 这是externs对象，它用来为未解析的导入符号和angr内部运行提供地址
>>> proj.loader.extern_object
<ExternObject Object cle##externs, maps [0x4000000:0x4008000]>

# 该对象为模拟系统调用提供地址
>>> proj.loader.kernel_object
<KernelObject Object cle##kernel, maps [0x5000000:0x5008000]>

# 最后，你可以获得给定地址对象的引用
>>> proj.loader.find_object_containing(0x400000)
<ELF Object fauxware, maps [0x400000:0x60105f]>
```

你可以直接与这些对象交互，从中提取数据

```python
>>> obj = proj.loader.main_object

# 对象的入口点
>>> obj.entry
0x400580

>>> obj.mmin_addr, obj.max_addr
(0x400000, 0x60105f)

# 查看ELF文件的段（segmets）和节（section）
>>> obj.segments
<Regions: [<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>,
           <ELFSegment memsize=0x238, filesize=0x228, vaddr=0x600e28, flags=0x6, offset=0xe28>]>
>>> obj.sections
<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>,
           <.interp | offset 0x238, vaddr 0x400238, size 0x1c>,
           <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>,
            ...etc

# 你可以给定地址获取特定的段和节
>>> obj.find_segment_containing(obj.entry)
<ELFSegment memsize=0xa74, filesize=0xa74, vaddr=0x400000, flags=0x5, offset=0x0>
>>> obj.find_section_containing(obj.entry)
<.text | offset 0x580, vaddr 0x400580, size 0x338>

# 获取符号在PLT表中的地址，或根据地址取得相应的符号
>>> addr = obj.plt['strcmp']
>>> addr
0x400550
>>> obj.reverse_plt[addr]
'strcmp'

# 显示对象的预链接基地址及它实际被CLE映射到内存中的地址
>>> obj.linked_base
0x400000
>>> obj.mapped_base
0x400000
```

## 符号和重定位（Symbols and Relocations）

你也可以使用CLE操作符号。符号是可执行文件中的一个重要的概念，实现了名称到地址的映射。

从CLE中获取一个符号最简单的方法是使用`loader.find_symbol`，它接收一个符号名或地址作为参数，返回一个符号对象

```python
>>> strcmp = proj.loader.find_symbol('strcmp')
>>> strcmp
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

一个符号最有用的属性是它的名称、所有者和地址，但符号的地址表示不止一种，symbol对象地址有三种表示方式：

- `.rebased_addr`是符号在全局地址空间的地址，这就是在上面命令屏幕上输出的地址

- `.linked_addr`是它相对于二进制文件预链接（prelink）基址的地址。这个地址会在例如`readelf(1)`中显示

- `.relative_addr`是它相对于对象基地址的地址。这经常在文献中被使用（尤其在windows文档），被称为RVA（relative virtual address）

```python
>>> strcmp.name
'strcmp'

>>> strcmp.owner
<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>

>>> strcmp.rebased_addr
0x1089cd0
>>> strcmp.linked_addr
0x89cd0
>>> strcmp.relative_addr
0x89cd0
```

除了提供调试信息之外，符号对象也支持动态链接。libc提供了如strcmp等外部符号，而main程序需要使用它。如果我们让CLE直接从main对象给我们一个strcmp符号，它会告诉你这是个导入符号。导入符号并没有与之关联的有意义的地址，但它们提供了用于解析它们的引用，通过`.resolvedby`属性可以得到。

```python
>>> strcmp.is_export
True
>>> strcmp.is_import
False

# 在加载器层面，这条指令是find_symbol,因为它是执行了搜索命令查找符号
# 在一个特定的对象层面，这条指令是get_symbol，因为一个指定的名称只有一个符号与之对应
>>> main_strcmp = proj.loader.main_object.get_symbol('strcmp')
>>> main_strcmp
<Symbol "strcmp" in fauxware (import)>
>>> main_strcmp.is_export
False
>>> main_strcmp.is_import
True
>>> main_strcmp.resolvedby
<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```

通过链接在内存中将外部符号注册为导入符号由另一个概念“重定位”处理。重定位将[import]和外部符号匹配，将导出地址写入[location]，格式为[format]。使用`obj.relocs`可以看到一个对象完整的重定位表（重定位实例），或者使用`obj.imports`获取从符号名到重定位表项的映射，这里没有给出相应的外部符号

重定位对应的导入符号可以用`.symbol`访问，重定位写入的地址可通过Symbol对象的任何地址标识符得到，你也可以使用`.owner`获取对重定位对象的引用。

```python
# 重定位表项无法很好的打印, 所以这些地址是python内部的, 与angr无关
>>> proj.loader.shared_objects['libc.so.6'].imports
{'__libc_enable_secure': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce780>,
 '__tls_get_addr': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018358>,
 '_dl_argv': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2e48>,
 '_dl_find_dso_for_object': <cle.backends.elf.relocation.amd64.R_X86_64_JUMP_SLOT at 0x7ff5c6018588>,
 '_dl_starting_up': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fd2550>,
 '_rtld_global': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fce4e0>,
 '_rtld_global_ro': <cle.backends.elf.relocation.amd64.R_X86_64_GLOB_DAT at 0x7ff5c5fcea20>}
```

如果导入符号无法解析为任何外部符号，例如，一个需要的共享库无法找到，CLE会自动将其更新为外部对象（loader.extern_obj），表明CLE提供这个符号作为外部符号。

## 加载选项（Loading Options）

如果你使用`angr.Project`来加载某些内容，那么你传递给Project构造器的关键词参数会直接传递给`cle.Loader`。如果你想了解所有可以使用的参数，你应该查看[CLE API docs](https://api.angr.io/cle)。在下面我们会介绍一些重要且常用的选项。

### 基本选项（Basic Options）

`auto_load_libs`用来指定是否启用CLE自动加载共享库，默认开启。相反的，`except_missing_libs`，设置为true时如果二进制文件存在无法解析的共享库依赖时，会引发一个异常。

`force_load_libs`接收一个字符串列表，列表中的字符串被视为必须加载的共享库，或者你可以使用`skip_libs`传递一个字符串列表跳过指定共享库的解析。可以通过`ld_path`传递一个字符串列表或字符串作为共享库的额外检索路径，优先级高于程序所在目录、工作目录和系统共享库目录。

### 二进制加载选项（Pre-Binary Options）

CLE同样允许你指定一些仅适用于特定二进制对象的选项，可以使用`main_opts`和`lib_opts`参数传递选项字典来实现。`main_opts`是从选项名称到选项值的映射，`lib_opts`是从库名称到选项字典的映射。

你可以使用的选项由使用的后端（backend）决定，但一些常见的选项是通用的

- `backend`：使用哪种后端，值为类或名称

- `base_addr`：加载的基地址

- `entry_point`：程序入口点

- `arch`：使用架构的名称

例如：

```python
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

### 后端（Backends）

CLE目前有静态加载ELF、PE、CGC、Mach-O和ELF  core  dump 文件的后端，或者把文件加载到一个平坦地址。CLE在大多数情况下会自动检测并使用合适的后端。所以你无需手动指定使用的后端，除非你在做一些非常奇怪的事情。

你可以在选项字典中包含一个键来强制CLE使用特定的后端，但有些后端无法自动检测架构，需要手动指定所需架构。架构的键值无需匹配某一个架构列表，angr会通过几乎所有受支持架构的通用标识符来识别你所指定的架构。

要使用特定的后端，请指定下表的名称：

| 后端名       | 描述                             | 是否需要指定`arch` |
| --------- | ------------------------------ | ------------ |
| elf       | ELF静态加载器，以PyELFTools为基础        | 否            |
| pe        | PE静态加载器，以PEFile为基础             | 否            |
| mach-o    | Mach-o静态加载器，不支持动态链接和变基         | 否            |
| cgc       | Cyber Grand Challenge静态加载器     | 否            |
| backedgcc | CGC二进制文件静态加载器，允许指定内存和注册backers | 否            |
| elfcore   | ELF core dump文件静态加载器           | 否            |
| blob      | 作为平坦镜像加载文件                     | 是            |

## 符号函数简介（Symbolic Function Summaries）

默认情况下，Project尝试使用`SimProcedures`替换库函数的外部调用，SimProcedures实际上只是模仿库函数改变运行状态的函数。我们已经实现了许多函数作为SimProcedures。这些内置程序可以通过`angr.SIM_PROCEDURES`字典访问到。这个字典是两级的，首先指定包名称（如libc、posix、win32、stubs）再指定库函数名。使用SimProcedure来替代实际系统中的库函数可以使分析变得更容易，但也会增加一些潜在的不确定性。

如果给定的函数没有对应的SimProcedure：

- 如果`auto_load_libs=True`（这是默认值），那么真正的库函数将会被执行。这不一定是不是你想要的，具体取决于实际功能。libc中的一些函数分析起来可能十分复杂，可能会导致尝试执行它们的路径数激增。

- 如果`auto_load_libs=False`，Project会将它们解析成`ReturnUnconstrained`的SimProcedure，每次调用它都会返回一个唯一的无约束符号值

- 如果`use_sim_procedures=Flase`（这是`angr.Project`的参数，而不是`cle.Loader`的参数，默认是False），那么只有外部对象提供的符号会被SimProcedures替换，并且将被替换为`ReturnUnconstrained`，只返回一个符号值而不做其他的事。

- 你可以指定要排除的符号，使其不被SimProcedures替换。使用`angr.Project: exclude_sim_procedures_list`和`exclude_sim_procedures_func`

- 可以查看`angr.Project._register_object`的代码来了解确切的算法

### Hooking

angr可以将库代码替换为python的模拟，这种机制称为`hooking`，你也可以这么做！

在进行模拟执行时，angr在每一步都会检查是否有对应的hook函数，如果有，则运行hook函数内容而不是二进制代码。可以使用API`proj.hook（addr, hook）`，其中hook是一个SimProcedure实例。你可以通过`.is_hooked``.unhook``.hooked_by`来管理工程中的hooks。

另一个hook函数的替代API，使用`proj.hook(addr)`作为函数装饰器，你可以将现成的函数作为hook函数。如果你这么做，你可以选择是否指定一个`length`关键字，在hook函数完成后跳过指定长度的字节继续执行。

```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # 这是一个类
>>> proj.hook(0x10000, stub_func())  # 使用类的实例进行hook

>>> proj.is_hooked(0x10000)
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```

此外，你可以使用`proj.hook_symbol(name, hook)`，第一个参数是符号的名称，来hook符号所在的地址。一个非常重要的用途是扩展angr的内置SimProcedures库。因为这些库函数都是类，所以你可以创建它们的子类，重载它们的一些行为，然后在hook中使用你的子类。

## 到这里非常棒！（So far so good ！）

到目前为止，你应该对CLE加载程序和Project级别控制分析的环境有一个大致的了解。你还应该明白angr对使用SimProcedures将复杂的库函数hook做出了合理的尝试来简化分析。

要了解您可以使用CLE加载程序及后端可执行的所有操作，请查看[CLE API docs](https://api.angr.io/cle)

