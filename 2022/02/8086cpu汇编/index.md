# 8086CPU汇编


# 8086CPU汇编

### - 8086CPU有14个寄存器

- 数据寄存器：AX,BX,CX,DX

- 其他寄存器：CS:IP,SS:SP,DS,ES,SI,DI,BP,FLAG(PSW)

- 8086CPU每一个寄存器都是16位的，存放2个字节

- 通用寄存器都可以分为两个独立的8位寄存器使用，如AL（低8位）,AH（高8位）

- 16位CPU特征：
  
  - 运算器一次最多可以处理16位数据
  
  - 寄存器的最大宽度为16位
  
  - 寄存器和运算器之间的通路是16位的

### - 8086CPU有20根地址总线

- 8086CPU采用在内部用**两个16位地址**合成（地址加法器）的方法形成一个**20位**的物理地址

- **物理地址 = 段地址 * 16 + 偏移地址**（16进制地址左移一位）

- 推论：偏移地址为16位（0-FFFFH）-->一个段最大长度位64kb（$2^{16}$)

### - CS(Code Segment):IP(Instruction Pointer)

- CS:IP指向CPU当前所要执行指令的地址

- IP递增器：执行完一条指令后，IP自动递增该指令的长度，跳到下一条指令

- 8086CPU加电启动或复位后，设置CS=FFFFH，IP=0000H

- 修改CS:IP寄存器的值
  
  - 同时修改CS:IP的内容：`jmp 段地址：偏移地址`
  
  - 仅修改IP的内容：`jmp 某一合法寄存器`（mov ax xxxx，jmp ax）

### - DS(Data Segment)和[address]（偏移地址）

- 经由通用寄存器将数据送入DS寄存器
  
  ```nasm
  mov ax, 1000H
  mov ds, ax
  ```

- 使用[address]读写内存（确定好ds）
  
  ```nasm
  mov ax, [0]    //把偏移地址为0处内存的值送入ax
  mov [0], cx    //把cx中的值写入偏移地址为0的内存
  ```

### - 栈

- `push ax`：把ax中的值送入栈中

- `pop ax`：把从栈顶取出数据送入ax

- 8086CPU入栈和出栈都是以**字**（16位）为单位进行的

### - SS(Stack Segment):SP(Stack Pointer)

- `push ax`
  
  - SP = SP - 2
  
  - 将ax中的内容送入SS:SP指向的内存单元处，此时SS:SP指向新栈顶

- `pop ax`
  
  - 将SS:SP指向的内存单元中数据取出送入ax中
  
  - SP = SP + 2

- 栈空时SS:SP指向栈最高地址（栈底）的偏移地址+2

### - 伪指令

- 编译器执行，无法汇编成机器码

- 一个段
  
  - assume cs:段名-->寄存器与段的关联假设
  
  - 段名 segment
  
  - 段名 ends

- end：结束对源程序的编译

### - [BS]

- 作为偏移地址索引内存，默认段地址在ds中

- `mov ax [1000H]`只是将1000H作为值送入ax

- 经由bx寄存器才能将偏移地址为1000H的内容送入ax
  
  ```nasm
  mov bx, 1000H
  mov ax, [bx]
  ```

### - loop指令

- loop实现循环，cx寄存器作为循环累加器

- 格式
  
  - mov cx，循环次数
  
  - 标号：循环执行代码
  
  - loop 标号

- 执行loop时`cx = cx - 1`，判断cx不为0则继续循环

### - SI（Source Index）DI（Destination Index）

- 与bx功能相近，但不能拆为两个8位寄存器

- 用ds;si指向源数据地址，用ds:di指向目标数据地址

### - BP（Base Pointer）

- 作为偏移地址指向内存，段地址默认在SS中

### - div（division）指令

- 除法指令

- 除数：8位或16位，在寄存器或内存单元中

- 被除数：（默认）放在`ax`或`ax和dx`中
  
  - 除数8位，被除数16位--->>ax
  
  - 除数16位，被除数32位--->>ax（低16位）和dx（高16位）

- 结果
  
  - 商存放在ax中
  
  - 余数存放在dx中

### - jmp指令

- jmp short 标号
  
  - 段内短转移
  
  - 8位地址偏移，而非指定跳转地址

- jmp near 标号
  
  - 段内近转移
  
  - 16位地址偏移，而非指定跳转地址

- jmp far 标号
  
  - 段间转移，远转移
  
  - 指定段地址和偏移地址，修改CS:IP的值

- jmp 寄存器
  
  - 16位段内转移

### - jcxz指令

- 有条件转移指令，短转移

- 8位地址位移，而不是指定跳转地址

- jcxz 标号

- 当`cx=0`时跳转，`cx!=0`时不跳转

- loop指令，cx=0时跳出循环，cx！=0时继续循环

### - call，ret指令

- ret：用栈中的值修改IP的值

- retf：用栈中的值修改CS:IP的值

- call指令
  
  - 将当前的IP或CS:IP压入栈中
  
  - 转移（jmp）标号
  
  - call不能实现短转移（可近转移和短转移），除此之外和jmp指令原理相同

### - mul指令

- 存储位置
  
  - 都是8位：相乘的两个数存在al或内存中，结果存在ax中
  
  - 都是16位：相乘的两个数存在ax或内存中，结果存在dx（高位）和ax（低位）中

- 格式
  
  - mul 寄存器
  
  - mul内存单元

### - flag寄存器

- 8086CPU中flag寄存器的1,3,5,12,13,14,15位没有使用

- 记录上一条指令后的各种状态，随时改变

- ZF（Zero Flag）标志-6
  
  - 表示结果是否为0,值为1则表示0,值为0则表示非0
  
  - add、sub、mul、div、inc、or、and等运算指令会影响标志寄存器
  
  - mov、push、pop等传送指令对标志寄存器没有影响

- PF（Parity Flag）标志-2
  
  - 奇偶校验位，1为偶数，0为奇数

- SF（Sign Flag）标志-7
  
  - 符号（正负）标志位，1为负，0为正

- CF（Carry Flag）标志-0
  
  - 记录了进行**无符号运算**的时候运算结果的最高有效位`是否`向更高位的进位或借位，8位

- OF（Overflow Flag）标志-11
  
  - 进行**有符号数运算**时，超过了机器所能表达的范围，将产生溢出

- DF（Direction Flag）标志-10
  
  - 方向标志位，在串处理指令中，控制每次操作后si,di的增减
  
  - DF=0,每次操作后si,di递增，cld指令设置为0
  
  - DF=1,每次操作后si,di递减，std指令设置为1

- IF（Interrupt Flag）标志-9
  
  - 是否响应外部可屏蔽中断请求
  
  - 1-允许响应，0-不允许响应

- TF（Trace Flag）标志-8
  
  - 当TF为1时，CPU进入单步调试模式，执行完每一条指令后产生单步中断

- AF（Auxiliary Carry Flag）标志-4
  
  - 辅助进位标志，进位（借位）标志
  
  - 与CF区别：4位运算有进位（借位）则置1,主要在BCD码时用到

### - adc指令

- 带进位加法指令，利用了 CF位上记录的进位值

- 格式：adc ax, bx

- 实际：ax = ax + bx + CF
  
  ```nasm
  add ax, bx
  //等价于
  add al, bl
  adc ah, bh
  ```

### - sbb指令

- 带借位减法指令，利用了CF上记录的借位值

- 格式：sbb ax, bx

- 实际：ax = ax -bx - CF

### - cmp指令

- 格式：cmp 对象1, 对象2

- 功能：对象1-对象2，不保存结果，将对标志寄存器产生影响

- 例：cmp ax，ax
  
  - ZF=1
  
  - PF=1
  
  - SF=0
  
  - CF=0
  
  - OF=0

- 例：mov ax,8 mov bx, 3 cmp ax, bx
  
  - ZF=0
  
  - PF=1
  
  - SF=0
  
  - CF=0
  
  - OF=0

### - 根据cmp结果的转移指令

- //无符号数运算跳转

- je：等于则转移（ZF=1）

- jne：不等于则转移（ZF=0）

- jb：低于则转移（CF=1）

- jnb：不低于则转移（CF=0）

- ja：高于则转移（CF=0,ZF=0）

- jna：不高于则转移（CF=1或ZF=1）

### - movsb指令

- 以字节为单位传送字符串，将ds:si指向的内存单元中的字节送入es:di中，然后根据DF标志位同步递增或递减si,di的值

- 以字为单位传送：movsw

- rep movsb：根据cx中的值，重复执行后面的串传送指令，循环实现cx个字符的传送

### - pushf和popf指令

- pushf：将标志寄存器的值压栈

- popf：从栈中弹出数据，送入标志寄存器中

- 为直接访问标志寄存器提供了一种方法

### - 中断

- CPU处理突发事件的一个重要技术，处理完成后立即返回断点，继续工作

- 硬件中断
  
  - 外部中断：外部设备发出的中断请求，利用中断控制器可屏蔽
  
  - 内部中断：除法除数为0,溢出中断，不可屏蔽的中断

- 软件中断
  
  - 不是真正的中断，只是可被调用执行的一般程序以及DOS的系统功能调用（INT 21H）

- 中断优先权
  
  - 除法错误、溢出中断、软件中断
  
  - 不可屏蔽中断
  
  - 可屏蔽中断
  
  - 单步中断

- 中断类型码
  
  - 8086CPU用8位中断类型码索引中断处理程序
  
  - 中断类型码对应中断向量表中的地址指向中断处理程序

- 8086CPU中断过程
  
  - （从中断信息中）取得中断类型码
  
  - 标志寄存器的值入栈（保护标志位）-->>pushf
  
  - 设置标志寄存器8-TF和9-IF为0 -->>TF=0,IF=0
  
  - cs的内容入栈 -->>push CS
  
  - IP的内容入栈 -->>push IP
  
  - 从内存地址为`中断类型码*4`和`中断类型码*4+2`的两个字单元中读取中断处理程序的入口地址设置IP和CS

- 中断处理程序
  
  - 保存用到的寄存器
  
  - 处理中断
  
  - 恢复用到的寄存器
  
  - 用iret指令返回（pop IP pop CS popf）

### - int中断

- 内中断，引发中断过程

- 格式：int 中断类型码

- int 21中断：
  
  - int中断例程的4c号功能，即程序返回功能
  
  ```nasm
  mov ax，4c00h
  //等价于
  mov ah, 4ch    ;程序返回
  mov al, 0      ;返回值，0表示正常返回
  int 21h
  ```

### - CPU端口

- 利用`in`和`out`指令从指定端口中读或写数据

- 8位端口用al寄存器，访问16位端口用ax寄存器

### - shl和shr指令

- 逻辑移位指令

- 将一个寄存器或内存单元中的数据向左（右）移

- 将最后多余的一位写入CF中

- 最低位以0来补充

- 如果移动位数大于1,必须将移动位数放在cl中

### - CMOS RAM

- 70H是CMOS RAM地址（读取）端口，71H是写入端口

- CMOS RAM中存放着当前时间，以下信息长度均为1个字节
  
  - 秒：00H
  
  - 分：02H
  
  - 时：04H
  
  - 日：07H
  
  - 月：08H
  
  - 年：09H

### - bcd码

- 每4位表示一个十进制位

- 4位内部用二进制0000--1001表示0-9

