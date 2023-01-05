# linux下通过设置LD_PRELOAD环境变量hook动态链接库


## 动态链接概述

程序员在编写代码时，常常需要使用外部库。外部库有静态库和动态库之分，二者都是经过编译、汇编但未进行链接的二进制文件（ELF文件）。

二者区别在于下一步参与`链接`的方式：静态库用于静态链接，直接将静态库中的指令写入最终生成的可执行文件中。动态库用于动态链接，只将一些重定位和符号表信息“拷贝”到最终的可执行文件中。

动态链接相比于静态链接，优势在于得到的可执行文件小很多，可扩展性更好、更新迭代更容易（只需更改动态链接库而不用整个重新编译）。劣势也很明显：需要运行时动态加载库函数，消耗更多时间和资源（但在很多场合中这种消耗是值得的），再有就是兼容性降低：不同的机器上的同名动态库可能有所不同，产生兼容性问题。

## 代码中使用动态链接库的两种方式

### 加载时链接

需要包含头文件，但代码中无需多余的语句，示例如下：

`main.c`

```c
#include "lib.h"
int main() {
    func();
    return 0;
}
```

`lib.h`

```c
#include <stdio.h>
void func();
```

`lib.c`

```c
#include "lib.h"
void func() {
    puts("func is called");
}
```

生成动态链接库

```bash
gcc -fPIC --shared lib.c -o lib.so
```

使用动态链接库构建可执行文件

```bash
gcc -o main main.c lib.so
```

此时直接运行main会报错无法找到动态链接库，这里需要指定环境变量`LD_LIBRARY_PATH`

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./
```

然后运行`./main`就可以看见正常程序输出

### 运行时链接

使用`dlfcn.h`中封装的函数，在代码中需要的地方手动链接所需的动态库

此时不需要`lib.h`文件，可以直接在`lib.c`中编写函数逻辑：

```c
#include <stdio.h>
void func() {
    puts("func is called");
}
```

生成动态库`lib.so`

```bash
gcc -fPIC --shared lib.c -o lib.so
```

`main.c`

```c
#include <dlfcn.h>

int main() {
    // 打开动态链接库，获得动态链接库的handle
    void *handle = dlopen("./lib.so", RTLD_LAZY);
    // 定义func变量形式，准备接收func函数
    void (*func)();
    // 传入动态链接库的handle和寻找的符号
    func = dlsym(handle, "func");
    // 正常调用func函数
    func();
    return 0;
}
```

编译链接生成可执行文件

```bash
gcc -o main main.c
```

直接运行`./main`可正确执行函数

## 使用LD_PRELOAD进行hook

### hook的基本原理

编译器在进行链接时，会首先加载环境变量`LD_PRELOAD`所指向的动态链接库。由于链接的具体步骤（此处不赘述，详情可查阅csapp或其他资料），同名的符号不会被重复加载，所以我们可以使用自己的动态库“覆盖”原来程序使用动态库的一些符号，达到hook的目的

### 针对上述加载时链接的hook

编写`hook.c`，包含同名函数func：

```c
#include <stdio.h>
void func() {
    puts("func is hooked");
}
```

生成动态链接库`hook.so`

```bash
gcc -fPIC --shared hook.c -o hook.so
```

原来生成的`main`可执行文件不变（环境变量也不变），执行：

```c
LD_PRELOAD=./hook.so ./main
```

可以发现func函数执行的是`lib.c`中的代码，hook成功

### 无法针对运行时链接进行hook

显而易见的，运行时链接是指定了文件路径、获取制定文件中的符号，故无法通过LD_PRELOAD进行hook

### 针对libc库中默认符号的hook

明白了hook的原理很容易发现，我们自己写的func函数与libc库中默认符号没有什么本质的区别，故只要定义同名的符号，就可以实现同样的hook

此处以`sleep`函数为例，具体过程与上面无异，仅展示代码

`main.c`

```c
#include <stdio.h>

int main() {
    puts("hello, my friend");
    sleep(3);
    puts("bye");
    return 0;
}
```

`hook.c`

```c
#include <stdio.h>
void sleep() {
    puts("hacked by dx3906");
}
```

直接运行`./main`和使用环境变量`LD_PRELOAD=./hook.so ./main`会有截然不同的效果

### 通过hook到system函数get shell

这里仅仅是对此hook手段用途的一些畅想，实际上所用方法完全一致，这也是`LD_PRELOAD`进行hook极大的局限性。

在能够hook的情况下，只需把hook函数的内容变成system调用即可get shell

如把上个例子的`hook.c`改为如下：

```c
#include <stdlib.h>
void sleep() {
    system("/bin/sh");
}
```

原理已明，更多的用途读者可以尽情发挥想象力与创造力

以上，如有疏漏请师傅们指出。

