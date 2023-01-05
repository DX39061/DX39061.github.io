# ret跳转的简单控制流混淆


## 写在前面

- 想法来自[NCTF2022](https://github.com/X1cT34m/NCTF2022) ccccha题目

- 感谢`Cynosure`师傅愿意跟我分享出题脚本

## 混淆的目的

想要达到混淆的目的，我们首先要明白：

- 混淆是对抗静态分析的有效手段，经过混淆的程序仍可正常运行

- 经过控制流混淆，如IDA等逆向工具将无法正确生成伪代码，给逆向工程带来极大困难

## 混淆的原理

要想让IDA无法识别控制流，我们就不能使用常规的jmp系列跳转，这里采用修改返回地址+ret跳转的方式，相关汇编代码如下：

```nasm
push    rbx
push    rbx
pushfq
call    $+5
pop     rbx
add     rbx, 3Fh
mov     [rsp+16], rbx
popfq
pop     rbx
retn
```

`call $+5`是原地call，但同时会将下一条指令（即pop rbx）的地址压入栈，正常时作为调用结束时的返回地址。但下一句`pop rbx`直接将其取出放入rbx，紧接着对rbx加上一个值，然后覆盖`rsp+16`。后面两句两个pop，每次rsp+8，正好让原先`rsp+16`处的值位于栈顶。此时执行retn，就会跳转到栈顶的这个地址。整个过程用gdb调试一下会看得更清楚。

对于`ccccha`这道题，可参考笔者的[上一篇WriteUp](https://blog.dx39061.top/2022/12/nctf2022-ccccha-wp/)，详细地介绍了混淆的原理以及去除方法

## 添加混淆的过程

整体的思路是：

- 将用c写好的源代码先编译成汇编

- 用python脚本在汇编中添加混淆指令

- 编译汇编文件生成可执行文件

这里笔者首先用C语言写了一个简单的异或加密逻辑：

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // char flag[] = "flag{an_example_of_control_flow_obfuscation}";
    unsigned char key = 0x99;
    unsigned char enc[] = {255, 245, 248, 254, 226, 248, 247, 198, 252, 225, 248, 244, 233, 245, 252, 198, 246, 255, 198, 250, 246, 247, 237, 235, 246, 245, 198, 255, 245, 246, 238, 198, 246, 251, 255, 236, 234, 250, 248, 237, 240, 246, 247, 228};
    unsigned char input[50];
    scanf("%44s", input);
    for(int i = 0; i < 44; i++) {
        input[i] ^= key;
        if (input[i]!= enc[i]) {
            puts("wrong");
            exit(-1);
        }
    }
    puts("right");
    return 0;
}
```

然后通过`gcc -S main.c -o main.s`即可得到汇编文件

下面重点说一下python脚本的内容：

### 在每一句指令后添加jmp跳转

```python
# 读入汇编文件
with open("main.s", "r") as input:
    codes = input.read()

codes = codes.split('\n')    # 分割每一行汇编代码
print(len(codes))

# 添加jmp指令
res = ""
cnt = 1
for line in codes:
    if line == "":    # 空行直接略过
        continue
    elif line[-1] == ':' or line[0] == '.' or line[1] == '.': # 非代码行原样不动
        res += '\t' + line.strip() + '\n'
    else:
        res += '\t' + line.strip()
        res += "jmp .ML{}\n".format(cnt) # 添加jmp跳转
        res += ".ML{}:\n".format(cnt) # 添加跳转目标标签
        cnt += 1
with open("jmp.s", "w") as output: # 写入jmp.s文件
    output.write(res)
```

此时我们可以编译`jmp.s`得到可执行文件，确定可以正常运行

拖到IDA里，通过CFG可以清晰地看出，代码确实被切分成了一个个小部分

但是仍然可以正常反编译得到伪代码，且与不添加`jmp`指令几乎无差别，这说明了IDA可以轻易处理jmp这种显式跳转。

### 将jmp跳转替换为ret跳转

```python
# 把jmp跳转替换为ret跳转
codes = res.split('\n')
res_2 = ""
jmp_count = 0
target_count = 1
for line in codes:
    if "jmp .ML" not in line:    # 非跳转指令原样不动
        res_2 += line + '\n'
    else:
        res_2 += f'''
        pushq %rbx
        pushq %rbx
        pushfq
        .byte 0xe8   
        .byte 0x00
        .byte 0x00
        .byte 0x00
        .byte 0x00
        .CALL_LAB_{jmp_count}:
        popq %rbx
        addq $(.ML{target_count} - .CALL_LAB_{jmp_count}),%rbx
        movq %rbx, 16(%rsp)
        popfq
        popq %rbx
        ret        
'''
        jmp_count += 1
        target_count += 1
with open("junk.s", "w") as output:
    output.write(res_2)
```

通过将jmp跳转替换，跳转效果不变，编译后运行可执行程序功能正常

但此时再使用IDA打开，会发现已经无法正常反编译，代码块都是破碎的、找不到联系的，也无法进行静态分析

### More...

如`ccccha`这道题中一样，你可以向其中添加更多的花指令使问题变得更复杂，且混淆更不容易去除

