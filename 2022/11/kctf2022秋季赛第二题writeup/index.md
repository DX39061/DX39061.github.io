# KCTF2022秋季赛第二题WriteUp


## 62进制大数运算

如何面对一堆乱七八糟的函数保持冷静与耐心是这道题最大的难点（（

搜一下`IRtzloZ6iuB`会发现有关62进制的内容，结合`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`这个表基本可以确定。代码使用结构体存储大数，前四字节为位数len，后32字节为具体数据data，在IDA中可以自行创建结构体使代码更好看

然后就是漫长的复原函数的过程，最终IDA函数列表中`_main`函数上面从上到下依次是：

```c
base62_decode
base62_init
base62_cpy
base62_cmp
base62_add
base62_sub
base62_and
base62_or
base62_xor
base62_mul
base62_div
base62_mod
base62_mod_ret // 不修改参数值，返回值是结果
base62_shl
base62_shr
```

三个或四个参数的函数第一个参数储存结果，两个参数的函数使用返回值作结果（init和cpy两个函数除外）

复原main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int split_index; // edi
  int len; // eax
  int v6; // esi
  int v7; // eax
  char input; // [esp+8h] [ebp-40h] BYREF
  char v10[60]; // [esp+9h] [ebp-3Fh] BYREF
  __int16 v11; // [esp+45h] [ebp-3h]
  char v12; // [esp+47h] [ebp-1h]

  input = 0;
  memset(v10, 0, sizeof(v10));
  v11 = 0;
  v12 = 0;
  printf((int)"Input:");
  gets(&input);
  split_index = -1;
  len = 0;
  if ( !input )
    goto LABEL_20;
  do
  {
    if ( len >= 64 )
      break;
    if ( v10[len - 1] == '-' )
      split_index = len;
  }
  while ( v10[len++] );
  if ( split_index > 0
    && (v6 = len - split_index, len - split_index > 0)
    && base62_decode(&left, &input, split_index, a0123456789abcd) > 0
    && base62_decode(&right, &v10[split_index], v6 - 1, a0123456789abcd) > 0
    && (base62_decode(&mod_const, aIrtzloz6iub, strlen(aIrtzloz6iub), a0123456789abcd),
        base62_init(&tmp1, 0),
        base62_init(&tmp2, 0),
        base62_cmp(&left, &right) < 0)    // left < right
    && base62_cmp(&left, &mod_const) < 0    // left < mod_const
    && base62_cmp(&right, &mod_const) < 0 ) // right < mod_const
  {
    v7 = 0;
    while ( 1 )
    {
      j = v7 + 1;
      base62_add(&tmp1, &tmp1, &left);
      base62_add(&tmp2, &tmp2, &right);
      base62_mod(&tmp1, &tmp1, &mod_const);
      base62_mod(&tmp2, &tmp2, &mod_const);
      base62_init(&var1, 1);
      base62_sub(&var1, &tmp1, &var1);
      if ( !base62_cmp(&var1, &left) )
      {
        ++cnt;
        base62_mul(&var1, &var1, &left);
      }
      base62_init(&var2, 1);
      base62_add(&var2, &tmp2, &var2);
      if ( !base62_cmp(&var2, &right) )
      {
        ++cnt;
        base62_div(&var2, &mod_const, &right);
      }
      if ( cnt == 10 )
        break;
      v7 = j;
      if ( j >= 0x200000 )
        goto LABEL_20;
    }
    printf((int)"Success!\n");
    return 0;
  }
  else
  {
LABEL_20:
    printf((int)"Error.\n");
    return 0;
  }
}
```

可以发现，input是被`-`分开的左右两部分字符串，然后把这两部分字符串当作62进制数使用`base62_decode`函数转成10进制（16进制）存入`left`和`right`，`mod_const`是由62进制数`Bui6ZolztRI`解码得到的，计算得到是10的19次方。下面还有对left和right的限制，即`left < right < mod_const`

下面的while(1)循环中，只有cnt==0才能正常break输出Success，且通过交叉引用可以发现整个程序只有两个if中`++cnt`对cnt的值进行`w`引用，容易想到的check逻辑是：

$( left * j_1 - 1) mod 10^{19} = left$

$(right * j_2 + 1) mod 10^{19} = right$

且在$1 <= j < 0x200000$中，随着j增大，j1、j2总共满足10次。这对一个逆向壬实属超纲了，于是做的时候这道题到这就陷入了死局。

## 不起眼函数中暗藏关键逻辑

在复原各种函数时，我是一边动调，一边连蒙带猜，看出大概用途就直接把整个函数当作黑盒处理了。结束后看了看别队的wp，才发现在`base62_mul`和`base62_div`中末尾藏着两段关键的逻辑

```c
base62_init(&var1, 4);    // var1.data = 4
base62_shl(&var2.len, &var1.len, 3); // val2.data = 4 << 3 = 32
if ( cnt > 0 && *(_DWORD *)&mod_const.data[var2.data[0]] == var2.data[0] )
    {
      base62_add(&var1, &var1, &var2);    
        // var1.data = var1.data + var2.data = 4 + 32 = 36
      v12 = base62_mod_ret(&var1, j);
        // v12 = var1.data % j = 36 % 32 = 4
      mod_const.data[var1.data[0]] += 4;
      base62_shl(&var1.len, &var1.len, v12);
      base62_sub(&var2, &var1, &var2);
    }
```

```c
base62_init(&var1, 4);
base62_shl(&var2.len, &var1.len, 3);
if ( cnt > 0 && *(_DWORD *)&mod_const.data[var2.data[0]] == var2.data[0] )
      {
        base62_add(&var1, &var1, &var2); 
        v11 = base62_mod_ret(&var1, ::j);
        mod_const.data[var1.data[0]] += 4;
        base62_shl(&var1.len, &var1.len, v11);
        base62_sub(&var2, &var1, &var2);
      }
```

## 数组越界取值是新颖还是刁难

在上述两段隐藏的逻辑中,开头两句先把var1初始化为4，再把var1左移3等于32赋给var2，下面的判断`*(_DWORD *)&mod_const.data[var2.data[0]] == var2.data[0`，var2.data[0] == 32，而mod_const.data只有32位，故访问下标32处会发生数组越界，可以发现下一个四字节存的是main函数中的`j`，所以判断条件实际是`cnt > 0 && j == 32`

if块中代码首先把var1.data改成了36，此时访问`mod_const.data[var1.data[0]]`同样会出现越界，实际访问的其实是main函数中的cnt，使cnt += 4，两个if块共加8，加上外层两个加1刚好为10,符合题目条件。

此时再回到上面列出的等式，所求其实是j1 == j2 == 32时的特殊解

即

$$
\left\{
\begin{matrix}
( left * 32 - 1) mod 10^{19} = left \\
( right * 32 + 1) mod 10^{19} = right
\end{matrix}
\right.
$$

变形一下

$$
\left\{
\begin{matrix}
left * 31 = k_1 * 10^{19} + 1 \\
right * 31 = k_2 * 10^{19} - 1 \\ 
left, right, k_1, k_2 \in N^* \\
left < right < mod_const
\end{matrix}
\right.
$$

解得

```c
k1 = 12 
k2 = 19
left = 0x35b870a6eb0f7bdf 
right = 0x550eb25d9ed88421
```

把left和right转换成62进制数即可得最终序列号`ZSxZerX4xb4-jyvP7x12lI7`

