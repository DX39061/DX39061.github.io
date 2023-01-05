# NCTF2022 ccccha 花指令/混淆 详解


## ccccha

题目地址：https://github.com/X1cT34m/NCTF2022

这道题重点在去花/混淆，去完之后是个chacha20就不说了

花指令大致可分为三类：

### 1. push完啥也没干就pop

```nasm
push    rax
push    rbx
push    rdx
pop     rdx
pop     rbx
pop     rax
```

解决方案：全都nop掉，脚本如下：

```python
start = 0x1090
end = 0xB000

def nop(start_addr, len):
    patch_bytes(start_addr, b'\x90' * len)

for i in range(start, end):
    if get_bytes(i, 4) == b'SRZ[':
        nop(i, 4)
    if get_bytes(i, 6) == b'PSRZ[X':
        nop(i, 6)
    if get_bytes(i, 2) == b'RZ':
        nop(i, 2)
    if get_bytes(i, 4) == b'PRZX':
        nop(i, 4)
    if get_bytes(i, 2) == b'PX':
        nop(i, 2)
    if get_bytes(i, 2) == b'S[':
        nop(i, 2)
    if get_bytes(i, 4) == b'PS[X':
        nop(i, 4)
    if get_bytes(i, 4) == b'RPXZ':
        nop(i, 4)
```

### 2. 经典0xe8

```nasm
pushfq
push    rax
cmp     rax, 2022h
ja      short near ptr loc_1311+2
jle     short near ptr loc_1311+2
call    near ptr 489D6BFEh
```

解决方案：从pushfq到两个`0xe8`全部nop掉，以及两个`0xe8`后面是`pop rax`和`popfq`，也一块扬了，脚本如下：

```python
start = 0x1090
end = 0xB000

def nop(start_addr, len):
    patch_bytes(start_addr, b'\x90' * len)

for i in range(start, end):
    if get_bytes(i, 16) == b'\x9cPH=" \x00\x00w\x04~\x02\xe8\xe8X\x9d':
        nop(i, 16)
```

### 3. 修改函数返回地址并利用retn跳转

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

正是这种奇怪的跳转方式让IDA无法识别目标地址，形成了控制流混淆，也就无法F5。想要修复这个控制流，我们需要把这种隐式的跳转变成显式的jmp跳转，即可让IDA更好地分析

接下来难题就变成了如何构造jmp指令，这里需要我们对汇编和机器码有一个更深的理解，下面举例说明：

- `48 81 C3 3F 00 00 00`是`add     rbx, 3Fh`的机器码，其中前三字节`48 81 C3`表示`add rbx`，后四字节`3F 00 00 00`是所加的立即数`3Fh`

- `48 83 C3 82`是`add     rbx, 0FFFFFFFFFFFFFF82h`的机器码，可见当操作数为负数时，add的机器码由81变为83，同时参数值变成了低一字节

- `jmp`命令的机器码有三种
  
  - `EB 8位offset`：短跳转（short jump）跳转到256字节的范围内
  
  - `E9 16/32位offset`：近跳转（near jump）可跳转到同一个段内的任意地址
  
  - `EA ptr 16:16/32`：远跳转（far jump）可跳转到程序中任意地址
  
  此处我们选择E9，并且参数为32位offset（相对EIP的偏移）

patch脚本：

```python
start = 0x1090
end = 0xB000

for i in range(start, end):
    # 第一种add
    if get_bytes(i, 12) == b'SS\x9c\xe8\x00\x00\x00\x00[H\x81\xc3' and get_bytes(i+16, 8) == b'H\x89\\$\x10\x9d[\xc3':
        offset = int.from_bytes(get_bytes(i+12, 4), 'little') + 3   # +3 是由于patch后jmp的下一条指令地址与原来call的下一条指令地址相差3
        patch_bytes(i, b'\xe9' + offset.to_bytes(4, 'little') + b'\x90' * 19)
    # 第二种add
    if get_bytes(i, 12) == b'SS\x9c\xe8\x00\x00\x00\x00[H\x83\xc3' and get_bytes(i+13, 8) == b'H\x89\\$\x10\x9d[\xc3':
        offset = (int.from_bytes(get_bytes(i+12, 1), 'little') | 0xffffff00) + 3
        patch_bytes(i, b'\xe9' + offset.to_bytes(4, 'little') + b'\x90' * 16)
```

patch完成之后ida仍无法显示不对劲，此时需要patch program apply一下，然后重新打开IDA加载程序，即可正确反编译出伪代码，如下：

```c
__int64 __fastcall sub_8DED()
{
  __int64 v0; // rbp
  int i; // [rsp+10h] [rbp-140h]
  _DWORD v3[44]; // [rsp+18h] [rbp-138h] BYREF
  __int64 v4; // [rsp+CBh] [rbp-85h] BYREF
  int v5; // [rsp+D3h] [rbp-7Dh]
  char v6; // [rsp+D7h] [rbp-79h]
  _QWORD v7[4]; // [rsp+D8h] [rbp-78h] BYREF
  char v8; // [rsp+F8h] [rbp-58h]
  _QWORD v9[5]; // [rsp+108h] [rbp-48h] BYREF
  __int16 v10; // [rsp+130h] [rbp-20h]
  unsigned __int64 v11; // [rsp+140h] [rbp-10h]
  __int64 v12; // [rsp+148h] [rbp-8h]

  v12 = v0;
  v11 = __readfsqword(0x28u);
  v7[0] = 0x6A05A2805023EE57LL;
  v7[1] = 0x12CFEBEC73124005LL;
  v7[2] = 0xF060C3D29ED918C4LL;
  v7[3] = 0x45613036DB175B72LL;
  v4 = 0x143D83BD8A1337E6LL;
  v5 = -1868846699;
  v9[0] = 0x23CE4B73757CC05ELL;
  v9[1] = 0x708F01F3AC89BBA4LL;
  v9[2] = 0x62D45B4183317FC8LL;
  v9[3] = 0x4B50FC9DDC27A7A6LL;
  v9[4] = 0x385117386B2F9806LL;
  v10 = -4305;
  v8 = 0;
  v6 = 0;
  puts("input:");
  sub_8941();
  if ( strlen(s1) != 42 )
  {
    printf("Wrong!");
    exit(0);
  }
  sub_1090(v3, v7, &v4, 0x9E3779B9);
  sub_1F33(v3);
  for ( i = 0; i <= 41; ++i )
  {
    s1[i] ^= *((_BYTE *)v3 + i);
    s1[i] += i;
  }
  if ( !memcmp(s1, v9, 0x2AuLL) )
    printf("Right!");
  else
    printf("Wrong!");
  return 0LL;
}
```

```c
void __fastcall sub_1090(_DWORD *a1, _DWORD *a2, _DWORD *a3, int a4)
{
  memcpy(a1 + 16, a2, 0x20uLL);
  memcpy(a1 + 24, a3, 0xCuLL);
  qmemcpy(a1 + 28, "expand 32-byte k", 16);
  a1[32] = *a2;
  a1[33] = a2[1];
  a1[34] = a2[2];
  a1[35] = a2[3];
  a1[36] = a2[4];
  a1[37] = a2[5];
  a1[38] = a2[6];
  a1[39] = a2[7];
  a1[40] = a4;
  a1[41] = *a3;
  a1[42] = a3[1];
  a1[43] = a3[2];
}
```

```c
void __fastcall sub_1F33(_DWORD *a1)
{
  int i; // [rsp+24h] [rbp-1Ch]
  int j; // [rsp+28h] [rbp-18h]
  int k; // [rsp+2Ch] [rbp-14h]

  for ( i = 0; i <= 15; ++i )
    a1[i] = a1[i + 28];
  for ( j = 0; j <= 9; ++j )
  {
    printf(" \b");
    *a1 += a1[4];
    a1[12] = __ROL4__(a1[12] ^ *a1, 16);
    a1[8] += a1[12];
    a1[4] = __ROL4__(a1[4] ^ a1[8], 12);
    *a1 += a1[4];
    a1[12] = __ROL4__(a1[12] ^ *a1, 8);
    a1[8] += a1[12];
    a1[4] = __ROL4__(a1[4] ^ a1[8], 7);
    a1[1] += a1[5];
    a1[13] = __ROL4__(a1[13] ^ a1[1], 16);
    a1[9] += a1[13];
    a1[5] = __ROL4__(a1[5] ^ a1[9], 12);
    a1[1] += a1[5];
    a1[13] = __ROL4__(a1[13] ^ a1[1], 8);
    a1[9] += a1[13];
    a1[5] = __ROL4__(a1[5] ^ a1[9], 7);
    a1[2] += a1[6];
    a1[14] = __ROL4__(a1[14] ^ a1[2], 16);
    a1[10] += a1[14];
    a1[6] = __ROL4__(a1[6] ^ a1[10], 12);
    a1[2] += a1[6];
    a1[14] = __ROL4__(a1[14] ^ a1[2], 8);
    a1[10] += a1[14];
    a1[6] = __ROL4__(a1[6] ^ a1[10], 7);
    a1[3] += a1[7];
    a1[15] = __ROL4__(a1[15] ^ a1[3], 16);
    a1[11] += a1[15];
    a1[7] = __ROL4__(a1[7] ^ a1[11], 12);
    a1[3] += a1[7];
    a1[15] = __ROL4__(a1[15] ^ a1[3], 8);
    a1[11] += a1[15];
    a1[7] = __ROL4__(a1[7] ^ a1[11], 7);
    *a1 += a1[5];
    a1[15] = __ROL4__(a1[15] ^ *a1, 16);
    a1[10] += a1[15];
    a1[5] = __ROL4__(a1[5] ^ a1[10], 12);
    *a1 += a1[5];
    a1[15] = __ROL4__(a1[15] ^ *a1, 8);
    a1[10] += a1[15];
    a1[5] = __ROL4__(a1[5] ^ a1[10], 7);
    a1[1] += a1[6];
    a1[12] = __ROL4__(a1[12] ^ a1[1], 16);
    a1[11] += a1[12];
    a1[6] = __ROL4__(a1[6] ^ a1[11], 12);
    a1[1] += a1[6];
    a1[12] = __ROL4__(a1[12] ^ a1[1], 8);
    a1[11] += a1[12];
    a1[6] = __ROL4__(a1[6] ^ a1[11], 7);
    a1[2] += a1[7];
    a1[13] = __ROL4__(a1[13] ^ a1[2], 16);
    a1[8] += a1[13];
    a1[7] = __ROL4__(a1[7] ^ a1[8], 12);
    a1[2] += a1[7];
    a1[13] = __ROL4__(a1[13] ^ a1[2], 8);
    a1[8] += a1[13];
    a1[7] = __ROL4__(a1[7] ^ a1[8], 7);
    a1[3] += a1[4];
    a1[14] = __ROL4__(a1[14] ^ a1[3], 16);
    a1[9] += a1[14];
    a1[4] = __ROL4__(a1[4] ^ a1[9], 12);
    a1[3] += a1[4];
    a1[14] = __ROL4__(a1[14] ^ a1[3], 8);
    a1[9] += a1[14];
    a1[4] = __ROL4__(a1[4] ^ a1[9], 7);
  }
  for ( k = 0; k <= 15; ++k )
    a1[k] += a1[k + 28];
  if ( !++a1[40] )
    ++a1[41];
}
```

```c
_BYTE *__fastcall sub_8941(__int64 a1)
{
  _BYTE *result; // rax
  char v2; // [rsp+23h] [rbp-Dh]
  int v3; // [rsp+24h] [rbp-Ch]

  v2 = getchar();
  v3 = 0;
  while ( v2 != '\n' )
  {
    *(_BYTE *)(a1 + v3++) = v2;
    v2 = getchar();
  }
  result = (_BYTE *)(v3 + a1);
  *result = 0;
  return result;
}
```

