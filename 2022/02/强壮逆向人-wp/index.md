# 强壮逆向人wp


# 第九周

## 0x00 Hacking with Google: Beginner

做了一半卡住了，偷看了一下[官方题解](https://github.com/luker983/google-ctf-2020/tree/master/reversing/beginner)，然后复现一下

ida很容易定位到主函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // er12
  __m128i v5; // [rsp+0h] [rbp-38h] BYREF
  __m128i s2[2]; // [rsp+10h] [rbp-28h] BYREF

  printf("Flag: ");
  __isoc99_scanf("%15s", &v5);
  s2[0] = _mm_xor_si128(
            _mm_add_epi32(_mm_shuffle_epi8(_mm_load_si128(&v5), (__m128i)SHUFFLE), (__m128i)ADD32),
            (__m128i)XOR);
  if ( !strncmp(v5.m128i_i8, (const char *)s2, 0x10uLL) && (v3 = strncmp((const char *)s2, EXPECTED_PREFIX, 4uLL)) == 0 )
  {
    puts("SUCCESS");
  }
  else
  {
    v3 = 1;
    puts("FAILURE");
  }
  return v3;
}
```

可以看到各种SSE指令

这里要注意add是把每四字节打包（pack）然后进行求和，而异或是逐字节进行异或

[_mm_shuffle_epi8](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_shuffle_epi8&ig_expand=7491,6382,4290,101,6382,7491,101) 无法见名知义，官方描述加查找各种解释终于搞懂，见注释

```c
FOR j := 0 to 15        //遍历16个字节
    i := j*8        //遍历每个字节中的8个bit
    IF b[i+7] == 1        //当前字节最高位为1
        dst[i+7:i] := 0 //整个字节8bit全置为0
    ELSE
        index[3:0] := b[i+3:i]    //相当于以int形式取出b中的值存入index
        dst[i+7:i] := a[index*8+7:index*8]  //把a数组下标为index[i]的值放入dst数组
    FI
ENDFOR
```

由于可见字符为32-126，不可能最高位为1，所以全置为0的情况不会发生

即shuffle就是把原数组a按b的顺序重新排列了一遍，其中值没有改变

题目验证逻辑

`flag->shuffle->add->xor == flag` && flag前四位为`CTF{` （这里注意输入的第16位是字符串结束标志\0

显然我们可以根据前四位推出一些东西

从后往前推

```c
flag    0x43  0x54  0x46  0x7b
xornum  0x76  0x58  0xB4  0x49
xor_pre 0x35  0x0c  0xf2  0x32

xor_pre 0x32f20c35  
addnum  0x0DEADBEEF
add_pre 0x54444d46

add_pre     0x46  0x4d  0x44  0x54
shufflenum  2     6      7     1
```

于是我们知道了第6、7位分别为M、D，即`CTF{--MD------}\0`

这时我们想到，最低位（字节）的值进行add操作时不会受其他字节的影响（不会受进位的影响

要确保已知字符是shuffle后的最低位，我们想到了\0，并且这次需要正着推

为省事写个脚本

```c
#include<stdio.h>
int xornum[] = {0x76, 0x58, 0xB4, 0x49, 0x8D, 0x1A, 0x5F, 0x38, 0xD4, 0x23, 0xF8, 0x34, 0xEB, 0x86, 0xF9, 0xAA};
int addnum[] = {0xEF, 0xBE, 0xAD, 0xDE, 0xAD, 0xDE, 0xE1, 0xFE, 0x37, 0x13, 0x37, 0x13, 0x66, 0x74, 0x63, 0x67};
int shufflenum[] = {2,6,7,1,5,11,9,14,3,15,4,8,10,12,13,0};
int main(){
    int alpha,index,pre_index;    //index是shuffle之后的下标，pre_index是shuffle之前的下标
    scanf("%x%d",&alpha,&index);
    for (int i = 0; i < 16; i++){
        if(index==shufflenum[i])
        pre_index = i;
    }
    unsigned char newalpha = ((alpha+addnum[pre_index]))^xornum[pre_index];
    printf("0x%x %c %d",newalpha,newalpha,pre_index);
}
// input:0 15
// output:0x30 0 9
// input:0x7b 3
// output:0x66 f 8
```

于是得到了flag第九位为0，即`CTF{--MD-0----}\0`

同样用 { 可以得到第8位为 f，即`CTF{--MDf0----}\0`

但我们已经用完了所有的最低字节

我们如果使用其他字节就会面临进位的问题，但我们也不排除还有其他没有使用的，没有进位的字符

如果去考虑一遍所有的位是否存在进位问题是一个浩大的工程

所以我们的想法是碰碰运气，如果推出的字符与已知矛盾就舍弃，如果不矛盾就保留（这真是官方方法

在把所有位试过一遍之后，我们会逐渐得到flag

```c
CTF{--MDf0-M--}\0
CTF{-1MDf0-M--}\0
CTF{S1MDf0-M--}\0
CTF{S1MDf0rM--}\0
CTF{S1MDf0rM3-}\0
CTF{S1MDf0rM3!}\0
CTF{S1MDf0rM3!}\0
```

## 0x01 V&N 公开赛 CSRe

die查，发现protector: Eazfuscator

查了一下，是一种.Net代码混淆方法，可以用de4dot反混淆，然后dnspy反编译

这道题需要耐心，尝试搜索flag字符串，翻了十多分钟终于找到Main

```c#
using System;
using System.Security.Cryptography;
using System.Text;

// Token: 0x02000006 RID: 6
internal sealed class Class3
{
    // Token: 0x0600000D RID: 13 RVA: 0x000022C8 File Offset: 0x000004C8
    public string method_0(string string_0, string string_1)
    {
        string text = string.Empty;
        char[] array = string_0.ToCharArray();
        char[] array2 = string_1.ToCharArray();
        int num = (array.Length < array2.Length) ? array.Length : array2.Length;
        for (int i = 0; i < num; i++)
        {
            text += (int)(array[i] ^ array2[i]);
        }
        return text;
    }

    // Token: 0x0600000E RID: 14 RVA: 0x0000231C File Offset: 0x0000051C
    public static string smethod_0(string string_0)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(string_0);
        byte[] array = SHA1.Create().ComputeHash(bytes);
        StringBuilder stringBuilder = new StringBuilder();
        foreach (byte b in array)
        {
            stringBuilder.Append(b.ToString("X2"));
        }
        return stringBuilder.ToString();
    }

    // Token: 0x0600000F RID: 15 RVA: 0x00002374 File Offset: 0x00000574
    private static void Main(string[] args)
    {
        if (!Class1.smethod_1())
        {
            return;
        }
        bool flag = true;
        Class3 @class = new Class3();
        string str = Console.ReadLine();
        if (Class3.smethod_0("3" + str + "9") != "B498BFA2498E21325D1178417BEA459EB2CD28F8")
        {
            flag = false;
        }
        string text = Console.ReadLine();
        string string_ = Class3.smethod_0("re" + text);
        string text2 = @class.method_0(string_, "63143B6F8007B98C53CA2149822777B3566F9241");
        for (int i = 0; i < text2.Length; i++)
        {
            if (text2[i] != '0')
            {
                flag = false;
            }
        }
        if (flag)
        {
            Console.WriteLine("flag{" + str + text + "}");
        }
    }
}

```

可以看到flag由两部分组成，即str和text

class。method_0像是个加密算法，得到两串字符串

直接丢到Cmd5网站解密，原来是Sha1加密

得到`"3" + str + "9"`==314159,`"re" + text` ==return

故flag{1415turn}

## 0x02 Zer0pts2020 easy-strcmp

ida载入，main函数

```c#
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  if ( a1 > 1 )
  {
    if ( !strcmp(a2[1], "zer0pts{********CENSORED********}") )
      puts("Correct!");
    else
      puts("Wrong!");
  }
  else
  {
    printf("Usage: %s <FLAG>\n", *a2);
  }
  return 0LL;
}
```

醒目的strcmp和一串字符串，难道这就是flag？肯定不是

翻函数列表发现两个特别的函数

```c#
int (**sub_563477E00795())(const char *s1, const char *s2)
{
  int (**result)(const char *, const char *); // rax

  result = &strcmp;
  qword_563478001090 = (__int64 (__fastcall *)(_QWORD, _QWORD))&strcmp;
  off_563478001028 = sub_563477E006EA;
  return result;
}
```

```c#
__int64 __fastcall sub_563477E006EA(__int64 a1, __int64 a2)
{
  int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    ;
  v4 = (i >> 3) + 1;
  for ( j = 0; j < v4; ++j )
    *(_QWORD *)(8 * j + a1) -= qword_563478001060[j];
  return qword_563478001090(a1, a2);
}
```

可以看到第一个函数sub_563477E00795记录了strcmp函数的地址，然后调用了函数sub_563477E006EA

相当于把strcmp函数给改了，实际执行的是第二个函数sub_563477E006EA

即把真正的flag加密了，然后与main函数里的字符串比较

这里注意main函数里传的是 a2[1]，即跳过了zer0pts

qword_563478001060刚好32个字节非空，对应修改 * 及其中间字符共32个字节

于是写脚本拿flag

```c#
#include<stdio.h>
unsigned char key[] =
{
  0x42, 0x09, 0x4A, 0x49, 0x35, 0x43, 0x0A, 0x41, 0xF0, 0x19, 
  0xE6, 0x0B, 0xF5, 0xF2, 0x0E, 0x0B, 0x2B, 0x28, 0x35, 0x4A, 
  0x06, 0x3A, 0x0A, 0x4F
};
char en_flag[]="********CENSORED********";
unsigned long long flag[5];
int main(){
    for(int i=0;i<3;i++){
        flag[i]=*((unsigned long long *)key+i)+*((unsigned long long *)en_flag+i);
    }
    for(int i=0;i<24;i++){
        printf("%c",*((unsigned char *)flag+i));
    }
}
//zer0pts{l3ts_m4k3_4_DETOUR_t0d4y}
```

刚开始还犯了错误，逐字节解密得到错误flag：`l3ts_m4k3^4^DDSOUR_t0d4y`

因为题目是将每8字节打包进行加法，其中有进位，而逐字节加法不会产生进位，所以出了问题

# 第八周

## 0x00 大佬喝茶~

偷懒没有管花指令

ida载入，进main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int j; // [rsp+14h] [rbp-7Ch]
  int i; // [rsp+18h] [rbp-78h]
  char input[48]; // [rsp+20h] [rbp-70h] BYREF
  char v7[32]; // [rsp+50h] [rbp-40h] BYREF
  __int64 v8[4]; // [rsp+70h] [rbp-20h] BYREF

  v8[3] = __readfsqword(0x28u);
  v8[0] = 0x4837F6D54BAA4D13LL;
  v8[1] = 0x203F4E88752F3489LL;
  printf("Hello there. Plz Input your flag: ");
  __isoc99_scanf("%40s", input);
  if ( strlen(input) != 32 )
  {
    printf("nope\n");
    exit(0);
  }
  for ( i = 0; i < 32; ++i )
    v7[i] = input[i];
  ((void (__fastcall *)(__int64 *, char *, __int64))sub_1180)(v8, v7, 4LL);
  for ( j = 0; j < 32; ++j )
  {
    if ( (unsigned __int8)v7[j] != en_flag[j] )
    {
      printf("nope\n");
      exit(0);
    }
  }
  printf("you are right!\n");
  return 0LL;
}
```

可以看出就是把input复制给v7然后经sub_1180函数加密然后和en_flag比较

跟进sub_1180

```c
__int64 __fastcall sub_1180(unsigned int *a1, __int64 a2, unsigned int a3)
{
  unsigned int v4; // [rsp+0h] [rbp-4Ch]
  unsigned int v5; // [rsp+4h] [rbp-48h]
  unsigned int v6; // [rsp+8h] [rbp-44h]
  unsigned int v7; // [rsp+Ch] [rbp-40h]
  unsigned int j; // [rsp+14h] [rbp-38h]
  unsigned int i; // [rsp+18h] [rbp-34h]
  int v10; // [rsp+1Ch] [rbp-30h]
  unsigned int v11; // [rsp+20h] [rbp-2Ch]
  unsigned int v12; // [rsp+24h] [rbp-28h]

  v7 = _byteswap_ulong(*a1);
  v6 = _byteswap_ulong(a1[1]);
  v5 = _byteswap_ulong(a1[2]);
  v4 = _byteswap_ulong(a1[3]);
  for ( i = 0; i < a3; ++i )
  {
    v10 = 0;
    v12 = *(unsigned __int8 *)(a2 + 8 * i + 3) | (*(unsigned __int8 *)(a2 + 8 * i + 2) << 8) | (*(unsigned __int8 *)(a2 + 8 * i + 1) << 16) | (*(unsigned __int8 *)(a2 + 8 * i) << 24);
    v11 = *(unsigned __int8 *)(a2 + 8 * i + 7) | (*(unsigned __int8 *)(a2 + 8 * i + 6) << 8) | (*(unsigned __int8 *)(a2 + 8 * i + 5) << 16) | (*(unsigned __int8 *)(a2 + 8 * i + 4) << 24);
    for ( j = 0; j < 0x20; ++j )
    {
      v10 -= 1640531527;
      v12 += (v6 + (v11 >> 5)) ^ (v10 + v11) ^ (v7 + 16 * v11);
      v11 += (v4 + (v12 >> 5)) ^ (v10 + v12) ^ (v5 + 16 * v12);
    }
    *(_BYTE *)(a2 + 8 * i) = HIBYTE(v12);
    *(_BYTE *)(a2 + 8 * i + 1) = BYTE2(v12);
    *(_BYTE *)(a2 + 8 * i + 2) = BYTE1(v12);
    *(_BYTE *)(a2 + 8 * i + 3) = v12;
    *(_BYTE *)(a2 + 8 * i + 4) = HIBYTE(v11);
    *(_BYTE *)(a2 + 8 * i + 5) = BYTE2(v11);
    *(_BYTE *)(a2 + 8 * i + 6) = BYTE1(v11);
    *(_BYTE *)(a2 + 8 * i + 7) = v11;
  }
  return 0LL;
}
```

能看出来就是tea加密

_byteswap_ulong这个细节需要注意，用处是把参数值以字节为单位颠倒前后顺序，也可以直接动调得到，即为key密钥

写脚本拿flag

```c
#include<stdio.h>

unsigned char en_flag[32] ={104,16,10,183,126,253,224,41,184,177,19,193,252,91,54,195,103,70,92,25,222,185,88,154,107,135,19,206,70,106,56,107};
// int key[]={0x4BAA4D13,0x4837F6D5,0x752F3489,0x203F4E88};
unsigned int key[]={0x134daa4b,0xd5f63748,0x89342f75,0x884e3f20};
int delta =0x61C88647,v9;
unsigned char flag[100];
unsigned int v10,v11;
int main(){
    for(int i=0;i<4;i++){
        *((char *)&v11+3)=*(en_flag + 8 * i);
        *((char *)&v11+2)=*(en_flag + 8 * i+1);
        *((char *)&v11+1)=*(en_flag + 8 * i+2);
        *((char *)&v11)=*(en_flag + 8 * i+3);
        *((char *)&v10+3)=*(en_flag + 8 * i+4);
        *((char *)&v10+2)=*(en_flag + 8 * i+5);
        *((char *)&v10+1)=*(en_flag + 8 * i+6);
        *((char *)&v10)=*(en_flag + 8 * i+7);
        for(int j=0x20-1;j>=0;j--){
            v9=(j+1)*delta*(-1);
            v10 -= (key[3] + (v11 >> 5)) ^ (v9 + v11) ^ (key[2] + 16 * v11);
            v11 -= (key[1] + (v10 >> 5)) ^ (v9 + v10) ^ (key[0] + 16 * v10);
        }
        *(flag + 8 * i) = *((char *)&v11+3);
        *(flag + 8 * i + 1) = *((char *)&v11+2);
        *(flag + 8 * i + 2) = *((char *)&v11+1);
        *(flag + 8 * i + 3) = *((char *)&v11);
        *(flag + 8 * i + 4) = *((char *)&v10+3);
        *(flag + 8 * i + 5) = *((char *)&v10+2);
        *(flag + 8 * i + 6) = *((char *)&v10+1);
        *(flag + 8 * i + 7) = *((char *)&v10);
    }
    puts(flag);
}
//19d9346d-410a-441f-b14e-9a60bb05
```

## 0x01 N1CTF oflo

太难啦~ 根据RX的wp复现还遇到了好多问题（（

ida打开只能看到start函数，点开offset main看到main函数全是红的，分析错误

![image](/upload/2022/02/image-fbb373ae1eca4665b1cef05045427137.png)

400BB1 jmp那一行明显有花指令，loc_400BB1自己跳到自己，先按u取消定义，BB2那一行按c转换为code，BB1patch成nop

![image](/upload/2022/02/image-69e2f7caab3b4905b28f5fa685a7d0f3.png)

BB7跳转到loc_400BBF，然后胡乱操作一通就retn了

![image](/upload/2022/02/image-8b40c0b9f4ca42f697e2626b4b628ec8.png)

因为return以后要执行BBC这一行，所以BBC这一行应该也是花指令

按u取消定义，把BBC patch掉，剩下两行转换成code，400CBA那一行同理

400D04和上面BB1同理，一样搞掉

![image](/upload/2022/02/image-242489444cb7441191832732b0bbf01e.png)

D14下面这几行一堆乱数据，不知道有没有用，先不管

回到main函数开头按p创建函数，成功，F5却出现报错

![image](/upload/2022/02/image-3605ccc5f5bd43e19468184e970b44ce.png)

是sp指针出了问题，可以通过Options->General->Disassembly右边勾上stack pointer

![image](/upload/2022/02/image-c11d5bc013674698956d2f9906ba71cc.png)

可以明显看到loc_400BBF函数中的sp指针值出了问题

这样看来，这个函数就是为了扰乱sp存在的，直接从BB7到BD0全patch掉

同理CB5到CCE也全patch掉

但这时ida把main函数断在了CB9这一行

![image](/upload/2022/02/image-ac520d37bc394e43bc551c30d7599dab.png)

可以回到main函数开始按u取消定义，然后按c重新转换为code

然后终于可以快乐地F5了,main函数真容：

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int i; // [rsp+4h] [rbp-23Ch]
  __int64 input[4]; // [rsp+10h] [rbp-230h] BYREF
  char v5[520]; // [rsp+30h] [rbp-210h] BYREF
  unsigned __int64 v6; // [rsp+238h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(v5, 0, 512uLL);
  input[0] = 0LL;
  input[1] = 0LL;
  input[2] = 0LL;
  input[3] = 0LL;
  if ( (unsigned int)sub_4008B9((__int64)v5) == -1 )
    exit(0LL);
  read(0LL, input, 19LL);
  qword_602048 = (__int64)sub_400A69;
  mprotect((unsigned int)main & 0xFFFFC000, 0x10uLL, 7uLL);
  for ( i = 0; i <= 9; ++i )
    *(_BYTE *)(qword_602048 + i) ^= *((_BYTE *)input + i % 5);
  if ( (unsigned int)sub_400A69((int)v5, (__int64)input + 5, (unsigned __int16)v5) )
    write(1LL, "Cong!\n", 6LL);
  exit(0LL);
}
```

17行创建了一个sub_400A69函数段的指针

18行[mprotect函数](https://blog.csdn.net/roland_sun/article/details/33728955)将sub_400A69段代码的权限改为7（即rwx）

然后20行修改了sub_400A69的代码，与input前5位（n1ctf）异或，即SMC，先写个脚本还原一下正确的代码

```c
from ida_bytes import *
key = "n1ctf"
for i in range(10):
    patch_byte(0x400A69+i,get_byte(0x400A69+i)^ord(key[i%5]))
```

还原之后F5还是失败，原因是有和main函数一样的花指令和扰乱sp的代码，一样处理后得到函数

```c
__int64 __fastcall sub_400A69(__int64 a1, __int64 a2)
{
  __int64 v2; // rbp
  int i; // [rsp+14h] [rbp-2Ch]
  char v5[14]; // [rsp+18h] [rbp-28h] BYREF
  unsigned __int64 v6; // [rsp+30h] [rbp-10h]
  __int64 v7; // [rsp+38h] [rbp-8h]

  v7 = v2;
  v6 = __readfsqword(0x28u);
  v5[0] = 53;
  v5[1] = 45;
  v5[2] = 17;
  v5[3] = 26;
  v5[4] = 73;
  v5[5] = 125;
  v5[6] = 17;
  v5[7] = 20;
  qmemcpy(&v5[8], "+;>=<_", 6);
  for ( i = 0; i <= 13; ++i )
  {
    if ( v5[i] != ((*(char *)(i + a1) + 2) ^ *(char *)(i + a2)) )
      return 0LL;
  }
  return 1LL;
}
```

重新进main函数看一下传进来的参数，这里需要再按一下F5，让ida根据修复后的代码重新分析一下

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int i; // [rsp+4h] [rbp-23Ch]
  __int64 input[4]; // [rsp+10h] [rbp-230h] BYREF
  char v5[520]; // [rsp+30h] [rbp-210h] BYREF
  unsigned __int64 v6; // [rsp+238h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(v5, 0, 0x200uLL);
  input[0] = 0LL;
  input[1] = 0LL;
  input[2] = 0LL;
  input[3] = 0LL;
  if ( (unsigned int)sub_4008B9((__int64)v5) == -1 )
    exit(0LL);
  read(0LL, input, 19LL);
  qword_602048 = (__int64)sub_400A69;
  mprotect((unsigned int)main & 0xFFFFC000, 16LL, 7LL);
  for ( i = 0; i <= 9; ++i )
    *(_BYTE *)(qword_602048 + i) ^= *((_BYTE *)input + i % 5);
  if ( (unsigned int)sub_400A69((__int64)v5, (__int64)input + 5) )
    write(1LL, "Cong!\n", 6LL);
  exit(0LL);
}
```

现在只需求出main函数里的v5即sub_400A69里的a1，即可解出flag

sub_4008B9里面实现太复杂了，想法是动调得到v5，但这里面有ptrace反调试

又因为反调试在输入之前，所以可以先运行到输出，然后再attach上去

这里我做的时候只有root用户运行可以，普通用户会报错权限不足什么的，具体原因不清楚

attach上之后main函数点进去v5，可以看到需要的前14位就是`Linux Version `

![image](/upload/2022/02/image-f45983ae22e14c029ce450a61d2965dc.png)

最后写脚本解flag

```c
#include<stdio.h>
char en_flag[]={53,45,17,26,73,125,17,20,'+',';','>','=','<','_'};
char v5[]="Linux Version ";
char flag[100];
int main(){
    for(int i=0;i<=13;i++){
        flag[i]=(v5[i]+2)^en_flag[i];
    }
    puts(flag);
}
// {Fam3_Is_NULL}
```

## 0x02 XNUCA 2020 Unravel MFC

没有最难，只有更难，这周已经做得心态爆炸了（（

开始连有用的函数都找不到，官方wp写得也有亿点简略，搞了几个小时也进展不大

先放放吧，后面再填坑

# 第七周

### 0×00 GUETCTF 2019 number game

拒 绝 暴 力

die查，Elf64，进ida

main函数东西有点多，一个一个看

```c
unsigned __int64 __fastcall main(int a1, char **a2, char **a3)
{
  _QWORD *v4; // [rsp+8h] [rbp-38h]
  __int64 v5; // [rsp+10h] [rbp-30h] BYREF
  __int16 v6; // [rsp+18h] [rbp-28h]
  __int64 v7; // [rsp+20h] [rbp-20h] BYREF
  __int16 v8; // [rsp+28h] [rbp-18h]
  char v9; // [rsp+2Ah] [rbp-16h]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v5 = 0LL;
  v6 = 0;
  v7 = 0LL;
  v8 = 0;
  v9 = 0;
  __isoc99_scanf("%s", &v5);
  if ( (unsigned int)sub_4006D6((const char *)&v5) )
  {
    v4 = sub_400758((__int64)&v5, 0, 10u);
    sub_400807((__int64)v4, (__int64)&v7);
    v9 = 0;
    sub_400881(&v7);
    if ( (unsigned int)sub_400917() )
    {
      puts("TQL!");
      printf("flag{");
      printf("%s", (const char *)&v5);
      puts("}");
    }
    else
    {
      puts("your are cxk!!");     //cai xu kun???
    }
  }
  return __readfsqword(0x28u) ^ v10;
}
```

sub_4006D6（）判断输入是否为数字0-4，且共10位

剩下几个函数可以倒着看

第二个if里面sub_4006D6（）的判断是一个5*5的数独逻辑

```html
1 4 # 2 3
3 0 # 1 #
0 # 2 3 #
# 3 # # 0
4 2 # # 1
```

手动填一下是0421421430

sub_400881(&v7)就是用上面的值填数独待检验

sub_400807（）应该只是复制了一下，v4->v7，动调验证确实啥也没干

主要加密函数是sub_400758（）

```c
_QWORD *__fastcall sub_400758(__int64 a1, int a2, unsigned int a3)
{
  char v5; // [rsp+1Fh] [rbp-11h]
  _QWORD *v6; // [rsp+28h] [rbp-8h]

  v5 = *(_BYTE *)(a2 + a1);
  if ( v5 == ' ' || v5 == '\n' || a2 >= (int)a3 )
    return 0LL;
  v6 = malloc(24uLL);
  *(_BYTE *)v6 = v5;
  v6[1] = sub_400758(a1, 2 * a2 + 1, a3);
  v6[2] = sub_400758(a1, 2 * (a2 + 1), a3);
  return v6;
}
```

递归，`2 * a2 + 1`，`2 * (a2 + 1)`，第一感觉是二叉树访问左右子树，没点OI基础都做不了逆向（（

动调验证一下，实际是通过对input按数组下标建立二叉树，然后输出中序遍历

于是可以根据0421421430手动建树，这里因为默认二叉树从左到右生长，所以保证了答案的唯一性

```c
       1
    1     3
  4   2  4  0
0  2  4
//flag：1134240024
```

## 0x01 HITCTF 2020 Node

没想法，没思路，verify函数上千行代码劝退（（

只能拜读RX的wp

原来只要找到345行一逆就行`while ( (char)(*((_BYTE *)v124 + v37) ^ 'r') + 'h' == key[v37] )`

```c
#include<stdio.h>
unsigned char key[] =
{
  0x93, 0x85, 0x69, 0x82, 0x83, 0x84, 0x85, 0xC7, 0x69, 0xBA, 
  0x6D, 0x7B, 0x84, 0x6E, 0xBA, 0x7B, 0xBA, 0x7D, 0x83, 0x68, 
  0x86, 0x7C, 0x68, 0x83, 0x7F, 0x84, 0x7E, 0xC6, 0x6D, 0x6F, 
  0x6D, 0x6F
};
char flag[100];
int main(){
    for(int i=0;i<32;i++){
        flag[i]=(key[i]-'h')^'r';
    }
    puts(flag);
}
//Yoshino-s want a girlfriend,wuwu
```

难点在于根本找不到

根据bb的wp获得思路，既然逆出来的东西要用来做web，那么一定在export窗口能找到

打开export窗口很显眼地就能看到`key`

![image](/upload/2022/02/image-ac16fef115c64503989ed335fa1603c8.png)

查交叉引用就能找到verify函数，就能定位345行，问题解决，又长见识了

### 0×02 GKCTF 2020 BabyDriver

die查，PE64，进ida

翻string窗口看到了

`.data:0000000140003000    000000E1    C    ****************o.*..*......*..**.**...**.*.*.***.****.**.*.*.***.......*.*.*****..***..*..**..***....**....**....***..**.***.***....**...***.**********..***......#****.*****************************`

打开果然是个地图，共225byte

刚开始还以为是`15*5`，后面看代码觉得不对，最后确定是`14*16`

```c
****************
o.*..*......*..*
*.**...**.*.*.**
*.****.**.*.*.**
*...**....*.*.**
***..***.**.*..*
*.**.***.**.**.*
*.**.******.**.*
*.**....***.**.*
*.*****.***....*
*...***.********
**..***......#**
**.*************
****************
```

根据地图查交叉引用定位走地图逻辑函数

```c

__int64 __fastcall sub_140001380(__int64 a1, __int64 a2)
{
  __int64 v3; // rdi
  __int64 v4; // rax
  int v5; // ecx
  __int16 *v6; // rsi
  __int64 v7; // rbp
  __int16 v8; // dx
  char v9; // dl
  const CHAR *v10; // rcx

  if ( *(int *)(a2 + 48) >= 0 )
  {
    v3 = *(_QWORD *)(a2 + 24);
    v4 = *(_QWORD *)(a2 + 56) >> 3;
    if ( (_DWORD)v4 )
    {
      v5 = dword_1400030E4;
      v6 = (__int16 *)(v3 + 2);
      v7 = (unsigned int)v4;
      while ( *(_WORD *)(v3 + 4) )
      {
LABEL_28:
        v6 += 6;
        if ( !--v7 )
          goto LABEL_29;
      }
      byte_140003000[v5] = 46;
      v8 = *v6;
      if ( *v6 == 0x17 )
      {
        if ( (v5 & 0xFFFFFFF0) != 0 )
        {
          v5 -= 16;
          goto LABEL_21;
        }
        v5 += 208;
        dword_1400030E4 = v5;
      }
      if ( v8 == 0x25 )
      {
        if ( (v5 & 0xFFFFFFF0) != 208 )
        {
          v5 += 16;
          goto LABEL_21;
        }
        v5 -= 208;
        dword_1400030E4 = v5;
      }
      if ( v8 == 0x24 )
      {
        if ( (v5 & 0xF) != 0 )
        {
          --v5;
          goto LABEL_21;
        }
        v5 += 15;
        dword_1400030E4 = v5;
      }
      if ( v8 != 0x26 )
        goto LABEL_22;
      if ( (v5 & 0xF) == 15 )
        v5 -= 15;
      else
        ++v5;
LABEL_21:
      dword_1400030E4 = v5;
LABEL_22:
      v9 = byte_140003000[v5];
      if ( v9 == 42 )
      {
        v10 = "failed!\n";
      }
      else
      {
        if ( v9 != 35 )
        {
LABEL_27:
          byte_140003000[v5] = 111;
          goto LABEL_28;
        }
        v10 = "success! flag is flag{md5(input)}\n";
      }
      dword_1400030E4 = 16;
      DbgPrint(v10);
      v5 = dword_1400030E4;
      goto LABEL_27;
    }
  }
LABEL_29:
  if ( *(_BYTE *)(a2 + 65) )
    *(_BYTE *)(*(_QWORD *)(a2 + 184) + 3i64) |= 1u;
  return *(unsigned int *)(a2 + 48);
}
```

上下左右逻辑容易看出来，但值0x17,0x25什么的太奇怪了

偷看师傅们的wp知道了原来是键盘扫描码，[粘个链接](https://codetd.com/en/article/13337857)

```c
0x17-i-up

0x24-j-left

0x25-k-down

0x26-l-right

```

手动走一下：lkkkllklkkklllkkklllll

结果不对？？好吧得全大写再求md5

最终flag：flag{403950a6f64f7fc4b655dea696997851}

# 第六周

### 0×00 PyDis

附件是pyc，先想到uncompyle6

```c
C:\Users\DX3906\Desktop\t1>uncompyle6 pyre.cpython-39.pyc>2.py
# Unsupported bytecode in file pyre.cpython-39.pyc
# Unsupported Python version, 3.9.0, for decompilation
```

3.9不支持，痛苦开始

```python
import dis,marshal
f=open("pyre.cpython-39.pyc","rb").read()
code = marshal.loads(f[16:])
dis.dis(code)
```

先抄含树师傅的代码得字节码

```c
  1           0 BUILD_LIST               0
              2 LOAD_CONST               0 ((178, 184, 185, 191, 182, 165, 174, 191, 129, 183, 187, 176, 129, 169, 191, 167, 163))
              4 LIST_EXTEND              1
              6 STORE_NAME               0 (magic)

  2           8 LOAD_NAME                1 (input)
             10 LOAD_CONST               1 ('flag >>> ')
             12 CALL_FUNCTION            1
             14 STORE_NAME               2 (inp)

  4          16 LOAD_NAME                3 (list)
             18 LOAD_NAME                2 (inp)
             20 CALL_FUNCTION            1
             22 STORE_NAME               4 (flag)

  5          24 LOAD_NAME                5 (len)
             26 LOAD_NAME                4 (flag)
             28 CALL_FUNCTION            1
             30 LOAD_NAME                5 (len)
             32 LOAD_NAME                0 (magic)
             34 CALL_FUNCTION            1
             36 COMPARE_OP               3 (!=)
             38 POP_JUMP_IF_FALSE       54

  6          40 LOAD_NAME                6 (print)
             42 LOAD_CONST               2 ('qwq')
             44 CALL_FUNCTION            1
             46 POP_TOP

  7          48 LOAD_NAME                7 (exit)
             50 CALL_FUNCTION            0
             52 POP_TOP

  9     >>   54 LOAD_NAME                8 (range)
             56 LOAD_NAME                5 (len)
             58 LOAD_NAME                4 (flag)
             60 CALL_FUNCTION            1
             62 LOAD_CONST               3 (2)
             64 BINARY_FLOOR_DIVIDE
             66 CALL_FUNCTION            1
             68 GET_ITER
        >>   70 FOR_ITER                54 (to 126)
             72 STORE_NAME               9 (i)

 10          74 LOAD_NAME                4 (flag)
             76 LOAD_CONST               3 (2)
             78 LOAD_NAME                9 (i)
             80 BINARY_MULTIPLY
             82 LOAD_CONST               4 (1)
             84 BINARY_ADD
             86 BINARY_SUBSCR
             88 LOAD_NAME                4 (flag)
             90 LOAD_CONST               3 (2)
             92 LOAD_NAME                9 (i)
             94 BINARY_MULTIPLY
             96 BINARY_SUBSCR
             98 ROT_TWO
            100 LOAD_NAME                4 (flag)
            102 LOAD_CONST               3 (2)
            104 LOAD_NAME                9 (i)
            106 BINARY_MULTIPLY
            108 STORE_SUBSCR
            110 LOAD_NAME                4 (flag)
            112 LOAD_CONST               3 (2)
            114 LOAD_NAME                9 (i)
            116 BINARY_MULTIPLY
            118 LOAD_CONST               4 (1)
            120 BINARY_ADD
            122 STORE_SUBSCR
            124 JUMP_ABSOLUTE           70

 12     >>  126 BUILD_LIST               0
            128 STORE_NAME              10 (check)

 14         130 LOAD_NAME                8 (range)
            132 LOAD_NAME                5 (len)
            134 LOAD_NAME                4 (flag)
            136 CALL_FUNCTION            1
            138 CALL_FUNCTION            1
            140 GET_ITER
        >>  142 FOR_ITER                26 (to 170)
            144 STORE_NAME               9 (i)

 15         146 LOAD_NAME               10 (check)
            148 LOAD_METHOD             11 (append)
            150 LOAD_NAME               12 (ord)
            152 LOAD_NAME                4 (flag)
            154 LOAD_NAME                9 (i)
            156 BINARY_SUBSCR
            158 CALL_FUNCTION            1
            160 LOAD_CONST               5 (222)
            162 BINARY_XOR
            164 CALL_METHOD              1
            166 POP_TOP
            168 JUMP_ABSOLUTE          142

 17     >>  170 LOAD_NAME                8 (range)
            172 LOAD_NAME                5 (len)
            174 LOAD_NAME                0 (magic)
            176 CALL_FUNCTION            1
            178 CALL_FUNCTION            1
            180 GET_ITER
        >>  182 FOR_ITER                34 (to 218)
            184 STORE_NAME               9 (i)

 18         186 LOAD_NAME               10 (check)
            188 LOAD_NAME                9 (i)
            190 BINARY_SUBSCR
            192 LOAD_NAME                0 (magic)
            194 LOAD_NAME                9 (i)
            196 BINARY_SUBSCR
            198 COMPARE_OP               3 (!=)
            200 POP_JUMP_IF_FALSE      182

 19         202 LOAD_NAME                6 (print)
            204 LOAD_CONST               2 ('qwq')
            206 CALL_FUNCTION            1
            208 POP_TOP

 20         210 LOAD_NAME                7 (exit)
            212 CALL_FUNCTION            0
            214 POP_TOP
            216 JUMP_ABSOLUTE          182

 22     >>  218 LOAD_NAME                6 (print)
            220 LOAD_CONST               6 ('happy new year!')
            222 CALL_FUNCTION            1
            224 POP_TOP
            226 LOAD_CONST               7 (None)
            228 RETURN_VALUE
```

参考：[死磕字节码        ](https://www.cnblogs.com/yinguohai/p/11158492.html)[python官方文档](https://docs.python.org/3.7/library/dis.html) 分析逻辑

大概是这个意思（还是习惯写c

```c
#include<stdio.h>

char magic[]={178, 184, 185, 191, 182, 165, 174, 191, 129, 183, 187, 176, 129, 169, 191, 167, 163};
char flag[100];
int main(){
    scanf("%s",flag);
    for(int i=0;i<8;i++){
        char x=flag[2*i];
        flag[2*i]=flag[2*i+1];
        flag[2*i+1]=x;
    }
    for(int i=0;i<17;i++){
        flag[i]^=222;
        if(flag[i]!=magic[i]){
            puts("wrong");
            return 0;
        }
    }
    puts("write");
}
```

写脚本解密

```c
#include<stdio.h>
char en_flag[]={178, 184, 185, 191, 182, 165, 174, 191, 129, 183, 187, 176, 129, 169, 191, 167, 163};
int main(){
    for(int i=0;i<17;i++){
        en_flag[i]^=222;
    }
    for(int i=0;i<8;i++){
        char x=en_flag[2*i];
        en_flag[2*i]=en_flag[2*i+1];
        en_flag[2*i+1]=x;
    }
    puts(en_flag);
}
//flag{hapi_new_ya}
```

## 0×01 FlareOn4 IgniteMe

die查，无壳，PE32，进ida

主函数长这样

```c
void __noreturn start()
{
  DWORD NumberOfBytesWritten; // [esp+0h] [ebp-4h] BYREF

  NumberOfBytesWritten = 0;
  hFile = GetStdHandle(0xFFFFFFF6);
  dword_403074 = GetStdHandle(0xFFFFFFF5);
  WriteFile(dword_403074, aG1v3M3T3hFl4g, 0x13u, &NumberOfBytesWritten, 0);
  sub_4010F0(NumberOfBytesWritten);
  if ( sub_401050() )
    WriteFile(dword_403074, aG00dJ0b, 0xAu, &NumberOfBytesWritten, 0);
  else
    WriteFile(dword_403074, aN0tT00H0tRWe7r, 0x24u, &NumberOfBytesWritten, 0);
  ExitProcess(0);
}
```

sub_4010F0()这个函数好像什么也没干

主要加密在sub_401050()

```c
int sub_401050()
{
  int v1; // [esp+0h] [ebp-Ch]
  int i; // [esp+4h] [ebp-8h]
  unsigned int j; // [esp+4h] [ebp-8h]
  char v4; // [esp+Bh] [ebp-1h]

  v1 = sub_401020(byte_403078);
  v4 = sub_401000();
  for ( i = v1 - 1; i >= 0; --i )
  {
    byte_403180[i] = v4 ^ byte_403078[i];
    v4 = byte_403078[i];
  }
  for ( j = 0; j < 0x27; ++j )
  {
    if ( byte_403180[j] != (unsigned __int8)byte_403000[j] )
      return 0;
  }
  return 1;
}
```

看一下里面代码能猜出来sub_401020()就是strlen()

v4直接动调就是0x4

写脚本解密

```c
#include<stdio.h>
char en_flag[]={13, 38,73, 69, 42, 23, 120, 68, 43, 108,93, 94, 69, 18, 47, 23, 43, 68, 111, 110,86, 9, 95, 69, 71, 115, 38, 10, 13, 19,23, 72, 66, 1, 64, 77, 12, 2, 105,0};
char flag[1000];
int main(){
    char V4=4;
    for(int i=39;i>=0;i--){
        flag[i]=en_flag[i]^V4;
        V4=flag[i];
    }
    puts(flag);
}
//flag;{R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com}
```

## 0x02 BUUCTF Firmware

这题难点在于工具的安装（（

跟着含树师傅的wp走

windows比较麻烦，直接开虚拟机先装binwalk,觉得慢可以换个源

```c
git clone https://github.com/devttys0/binwalk
cd binwalk
python setup.py install
```

先binwalk -e 拆包，四个文件，挨个file命令查看

有用的就是120200.squashfs，这里要用 firmware-mod-kit 的 unsquashfs_all.sh工具

然后就遇到了和bb师傅一样的问题，持续痛苦面具

![image](/upload/2022/02/image-57a26128130d401b8d5ff64e83169a96.png)

幸好RX神是万能的

发现问题是github仓库的源代码有问题

换一个仓库一切正常了

```c
git clone https://github.com/rampageX/firmware-mod-kit.git
cd firmware-mod-kit/src
./configure
make
```

利用uncramfs_all.sh拆120200.squashfs

发现/tmp里有个backdoor文件，这也太明显了，不过要是藏起来可能还真找不着

拖ida分析

先看string窗口直接就看到了 echo.byethost51.com

盲猜就是题目要的服务器地址，点进去看到变量名commServer，确信

查交叉引用找到了ininConnextion()函数

```c
bool initConnection()
{
  char *v0; // r0
  char s[512]; // [sp+4h] [bp-208h] BYREF
  int v3; // [sp+204h] [bp-8h]

  memset(s, 0, sizeof(s));
  if ( mainCommSock )
  {
    close(mainCommSock);
    mainCommSock = 0;
  }
  if ( currentServer )
    ++currentServer;
  else
    currentServer = 0;
  strcpy(s, (&commServer)[currentServer]);
  v3 = 36667;
  if ( strchr(s, 58) )
  {
    v0 = strchr(s, 58);
    v3 = atoi(v0 + 1);
    *strchr(s, 58) = 0;
  }
  mainCommSock = socket(2, 1, 0);
  return connectTimeout(mainCommSock, s, v3, 30) == 0;
}
```

盲猜端口号就是v3=36667，实在太像了

于是flag{MD5(echo.byethost51.com:36667)}=flag{33a422c45d551ac6e4756f59812a954b}

correct！

# 第五周

2021-11-29 
补上周，虽迟但到

## 0x00 DDCTF Android Easy

下载附件是个zip

后缀改为apk用jeb打开

打开FlagActivity文件看java

甚至都不用算((
![image](/upload/2022/02/image-7184b6e41bfb4b4ba2e499dba013585b.png)

flag{DDCTF-3ad60811d87c4a2dba0ef651b2d93476@didichuxing.com}

## 0x01 WELCOME TO JNI

```
【维基百科】
JNI （Java Native Interface，Java本地接口）是一种编程框架，使得Java虚拟机中的Java程序可以调用本地应用/或库，也可以被其他程序调用。 本地程序一般是用其它语言（C、C++或汇编语言等）编写的，并且被编译为基于本机硬件和操作系统的程序。
```

下载附件是apk，直接进jeb，打开MainActivity

```java
public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("native-lib");
    }

    public native boolean loginUtils(String arg1) {
    }

    @Override  // androidx.appcompat.app.AppCompatActivity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.setContentView(0x7F0B001C);  // layout:activity_main
        this.findViewById(0x7F080057).setOnClickListener(new View.OnClickListener() {  // id:button
            @Override  // android.view.View$OnClickListener
            public void onClick(View v) {
                boolean ok = MainActivity.this.loginUtils(((EditText)MainActivity.this.findViewById(0x7F0800B5)).getText().toString());  // id:inputBox
                Toast.makeText(MainActivity.this.getApplicationContext(), ok ? "RIGHT!!!!" : "WRONG!!!!", 1).show();
            }
        });
    }
}
```

经含树师傅指点得知`stem.loadLibrary("native-lib");`就是JNI的标志

把附件后缀改为zip，打开lib文件夹，里面即native-lib

四个文件夹内容基本一样，只是架构不同

随便拖一个进ida（一定要先解压。。。）

查string就能看到flag{welcome_to_naive_lib!}

## 0x02 Codegate CTF Redvelvet

die查，elf64，进ida，函数列表找main

```
v40 = __readfsqword(40u);
  strcpy(s2, "0a435f46288bb5a764d13fca6c901d3750cee73fd7689ce79ef6dc0ff8f380e5");
  v36 = 0LL;
  v37 = 0LL;
  v38 = 0LL;
  v39 = 0;
  printf("Your flag : ");
  fgets(&s, 27, edata);
  func1(s, v8);
  func2((unsigned int)v8, (unsigned int)v9);
  func3((unsigned int)v9, (unsigned int)v10);
  func4((unsigned int)v10, (unsigned int)v11);
  func5((unsigned int)v11, (unsigned int)v12);
  func6((unsigned int)v12, (unsigned int)v13, (unsigned int)v14);
  func7((unsigned int)v14, (unsigned int)v15, (unsigned int)v16);
  func8((unsigned int)v16, (unsigned int)v17, (unsigned int)v18);
  func9((unsigned int)v18, (unsigned int)v19, (unsigned int)v20);
  func10((unsigned int)v20, (unsigned int)v21, (unsigned int)v22);
  func11((unsigned int)v22, (unsigned int)v23, (unsigned int)v24);
  func12((unsigned int)v24, (unsigned int)v25, (unsigned int)v26);
  func13((unsigned int)v26, (unsigned int)v27, (unsigned int)v28);
  func14((unsigned int)v28, (unsigned int)v29, (unsigned int)v30);
  func15((unsigned int)v30, (unsigned int)v31, (unsigned int)v32);
  SHA256_Init((__int64)v6);
  v3 = strlen(&s);
  SHA256_Update(v6, &s, v3);
  SHA256_Final(v33, v6);
  for ( i = 0; i <= 31; ++i )
    sprintf(&s1[2 * i], "%02x", (unsigned __int8)v33[i]);
  if ( strcmp(s1, s2) )
    exit(1);
  printf("flag : {\" %s \"}\n", &s);
  return 0;
```

基本逻辑是对输入走15个function，然后SHA256加密和s2比较

直接上angr

但这里需要注意，SHA256不可逆，所以find直接设在cmp处angr算不出来

而从SHA256之前到cmp只有一条路，所以find设在加密之前就行了,而avoid设在exit()函数处就行

```
In [1]: import angr

In [2]: proj = angr.Project('./RedVelvet',auto_load_libs=False)

In [3]: state = proj.factory.entry_state()

In [4]: simgr = proj.factory.simgr(state)

In [5]: simgr.explore(find=0x401537,avoid=0x4007D0)
```

提示`Out[5]: <SimulationManager with 1 found, 63 avoid>`

输出

```
In [6]: print(simgr.found[0].posix.dumps(0))
b'What_You_Wanna_Be?:)_la_la'
```

这里说明一下，上面的是正确答案

但其实我第一次跑出来是`b'What_You_Wanna_Be?:)_lc_la`,差了一个字母

当我写这篇wp时又跑了一遍，答案却是对的

两次脚本完全一样，angr也都没提示多解，但输出却不同

这才印证了RX师傅所说，粘几张聊天记录
![image](/upload/2022/02/image-06e7926e7fac4f2684a9fcb2444132c0.png)
![image](/upload/2022/02/image-e0070c242c044f32a6d3526dcd285b64.png)

用我的话来说就是：

1.angr对于已经走通的路不会再走第二遍

2.每一次先走哪条路（得到哪个答案）是随机的

所以出问题时（angr计算不准确）大可以多来两遍（

# 第四周

2021-11-20

### 0x00 DMCTF2020 re3

> 一种常见的算法。

die查，ELF64，进ida

结合tips使用Findcrypt插件

函数列表定位main函数

```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  int i; // [rsp+1Ch] [rbp-C4h]
  char v6[96]; // [rsp+20h] [rbp-C0h] BYREF
  char v7[16]; // [rsp+80h] [rbp-60h] BYREF
  char s[32]; // [rsp+90h] [rbp-50h] BYREF
  char s1[40]; // [rsp+B0h] [rbp-30h] BYREF
  unsigned __int64 v10; // [rsp+D8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts(::s);
  memset(s, 0, 0x14uLL);
  read(0, s, 5uLL);
  sub_90A(v6);
  v3 = strlen(s);
  sub_956(v6, s, v3);
  sub_AA4(v6, v7);
  for ( i = 0; i <= 15; ++i )
    sprintf(&s1[2 * i], "%02x", (unsigned __int8)v7[i]);
  if ( !strcmp(s1, Big_Numbers1_203060) )
    printf("right");
  getchar();
  return 0LL;
}
```

Findcrypt结果

```
.data:0000000000203060    global    Big_Numbers1_203060    $c0    b'21232f297a57a5a743894a0e4a801fc3'
```

难道有种算法叫bignumbers？

百度无果，于是尝试搞懂加密逻辑，手动逆（天真.jpg)

然后就没有然后了（

偷看师傅们的题解,原来bignumbers是MD5的密文？？？

网站撞出flag{admin}

## 0x01 ACTF2020 Oruga

> 又是熟悉的迷宫……等下这是什么东西？
> die查，Elf64，进ida

迷宫逻辑函数

```
_BOOL8 __fastcall sub_78A(__int64 a1)
{
  int v2; // [rsp+Ch] [rbp-Ch]
  int v3; // [rsp+10h] [rbp-8h]
  int v4; // [rsp+14h] [rbp-4h]

  v2 = 0;
  v3 = 5;
  v4 = 0;
  while ( byte_201020[v2] != 33 )
  {
    v2 -= v4;
    if ( *(_BYTE *)(v3 + a1) != 'W' || v4 == -16 )
    {
      if ( *(_BYTE *)(v3 + a1) != 'E' || v4 == 1 )
      {
        if ( *(_BYTE *)(v3 + a1) != 'M' || v4 == 16 )
        {
          if ( *(_BYTE *)(v3 + a1) != 'J' || v4 == -1 )
            return 0LL;
          v4 = -1;
        }
        else
        {
          v4 = 16;
        }
      }
      else
      {
        v4 = 1;
      }
    }
    else
    {
      v4 = -16;
    }
    ++v3;
    while ( !byte_201020[v2] )
    {
      if ( v4 == -1 && (v2 & 0xF) == 0 )
        return 0LL;
      if ( v4 == 1 && v2 % 16 == 15 )
        return 0LL;
      if ( v4 == 16 && (unsigned int)(v2 - 240) <= 0xF )
        return 0LL;
      if ( v4 == -16 && (unsigned int)(v2 + 15) <= 0x1E )
        return 0LL;
      v2 += v4;
    }
  }
  return *(_BYTE *)(v3 + a1) == 125;
}
```

可以看出byte_201020是地图，共256byte，即16*16的地图

v2是当前所在的位置，v4是偏移量，1-right，-1-left，16-down，-16-up

上面的while里四个if可以直接对应else给v4赋值，即W-up E-right M-down J-left

下面的while函数里四个if应该是边界判断

然后循环一直往一个方向走，直到碰到字符

知道了这些，才能搞懂上面四个if里||v4==xx这个条件是在干啥

可以发现这个条件和下面else里给v4的赋值是一样的

即如果下一步和上一步是一样的，但上一步已经走到了这个方向所能走的最远处，这一步就是无效的

如果出现无效的重复命令，if判断会一路畅通，直接return 0

至此，手动走地图得flag：actf{MEWEMEWJMEWJM}
![image](/upload/2022/02/image-3a60818102104b73bd843b21b865d4de.png)

## 0×02 网鼎杯2020 signal

> 尝试一下某个自动化逆向工具？

感谢RX细心又耐心讲解符号执行

angr直接搞他

```
project = angr.Project('./signal.exe',auto_load_libs = False)
state = project.factory.entry_state()
simgr = project.factory.simgr(state)
simgr.explore(find = 0x40179E,avoid =0x401539)
print(simgr.found[0].posix.dumps(0))
```

得flag{757515121f3d478}，真香

# 第三周

2021-11-13

## 0×00 SUCTF2019 Signin

> 你认识这个算法嘛

不认识，然后根据题解先去学RSA和gmpy2库，断断续续学了几天（（

贴个链接吧，便于以后复习

[RSA](https://blog.csdn.net/dbs1215/article/details/48953589)    [gmpy2库常见函数](https://blog.csdn.net/weixin_43790779/article/details/108473984 "gmpy2库常见函数")

die查壳，无，然后进ida，直接根据函数列表定位main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[16]; // [rsp+0h] [rbp-4A0h] BYREF
  char v5[16]; // [rsp+10h] [rbp-490h] BYREF
  char v6[16]; // [rsp+20h] [rbp-480h] BYREF
  char v7[16]; // [rsp+30h] [rbp-470h] BYREF
  char v8[112]; // [rsp+40h] [rbp-460h] BYREF
  char v9[1000]; // [rsp+B0h] [rbp-3F0h] BYREF
  unsigned __int64 v10; // [rsp+498h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[sign in]");
  printf("[input your flag]: ");
  __isoc99_scanf("%99s", v8);
  sub_96A(v8, v9);
  __gmpz_init_set_str(v7, "ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str(v6, v9, 16LL);
  __gmpz_init_set_str(v4, "103461035900816914121390101299049044413950405173712170434161686539878160984549", 10LL);
  __gmpz_init_set_str(v5, "65537", 10LL);
  __gmpz_powm(v6, v6, v5, v4);
  if ( (unsigned int)__gmpz_cmp(v6, v7) )
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
  return 0LL;
}
```

根据RSA的形式稍微重命名一下变量

```
  v10 = __readfsqword(0x28u);
  puts("[sign in]");
  printf("[input your flag]: ");
  __isoc99_scanf("%99s", input);
  sub_96A(input, v9);
  __gmpz_init_set_str(c, "ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str(calc, v9, 16LL);
  __gmpz_init_set_str(n, "103461035900816914121390101299049044413950405173712170434161686539878160984549", 10LL);
  __gmpz_init_set_str(e, "65537", 10LL);
  __gmpz_powm(calc, calc, e, n);
  if ( (unsigned int)__gmpz_cmp(calc, c) )      // calc是根据input计算出的密文，c是实际的密文
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
  return 0LL;
```

先用yafu分解n，由于写这篇文章时是第二次分解n所以比较快

```
C:\Users\DX3906>D:\reserve\yafu\yafu-x64.exe
factor(103461035900816914121390101299049044413950405173712170434161686539878160984549)

fac: factoring 103461035900816914121390101299049044413950405173712170434161686539878160984549
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits

starting SIQS on c78: 103461035900816914121390101299049044413950405173712170434161686539878160984549

==== sieving in progress (1 thread):   36224 relations needed ====
====           Press ctrl-c to abort and save state           ====


SIQS elapsed time = 1.0985 seconds.
Total factoring time = 1.1195 seconds


***factors found***

P39 = 282164587459512124844245113950593348271
P39 = 366669102002966856876605669837014229419

ans = 1
```

得到 p=282164587459512124844245113950593348271 q=366669102002966856876605669837014229419

已知n,p,q,e，先求d

```python
import gmpy2
n=103461035900816914121390101299049044413950405173712170434161686539878160984549
p=282164587459512124844245113950593348271
q=366669102002966856876605669837014229419
e=65537
l=(p-1)*(q-1)
d=gmpy2.invert(e,l)
```

已知n,d,c,求明文

```python
c=0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
flag=gmpy2.powmod(c,d,n)
from Crypto.Util.number import *
print(long_to_bytes(flag))
# b'suctf{Pwn_@_hundred_years}'
```

## 0×01 FlareOn6 Overlang

die查看文件信息，PE32，拖进ida

竟然就三个函数，start函数应该是主要的

```c
int __stdcall start(int a1, int a2, int a3, int a4)
{
  CHAR Text[128]; // [esp+0h] [ebp-84h] BYREF
  int v6; // [esp+80h] [ebp-4h]

  v6 = sub_401160(Text, &unk_402008, 28);
  Text[v6] = 0;
  MessageBoxA(0, Text, Caption, 0);
  return 0;
}
```

sub_401160函数像是把unk_402008的前28位复制给Text，然后通过MessageBoxA输出Text和Caption

这里我们可以打开unk_402008看看

```
.rdata:00402008 unk_402008      db 0E0h                 ; DATA XREF: start+B↑o
.rdata:00402009                 db  81h
.rdata:0040200A                 db  89h
.rdata:0040200B                 db 0C0h
.rdata:0040200C                 db 0A0h
.rdata:0040200D                 db 0C1h
.rdata:0040200E                 db 0AEh
.rdata:0040200F                 db 0E0h
.rdata:00402010                 db  81h
.rdata:00402011                 db 0A5h
.rdata:00402012                 db 0C1h
.rdata:00402013                 db 0B6h
.rdata:00402014                 db 0F0h
.rdata:00402015                 db  80h ; €
.rdata:00402016                 db  81h
.rdata:00402017                 db 0A5h
.rdata:00402018                 db 0E0h
.rdata:00402019                 db  81h
.rdata:0040201A                 db 0B2h
.rdata:0040201B                 db 0F0h
.rdata:0040201C                 db  80h ; €
.rdata:0040201D                 db  80h ; €
.rdata:0040201E                 db 0A0h
.rdata:0040201F                 db 0E0h
.rdata:00402020                 db  81h
.rdata:00402021                 db 0A2h
.rdata:00402022                 db  72h ; r
.rdata:00402023                 db  6Fh ; o
.rdata:00402024                 db 0C1h
.rdata:00402025                 db 0ABh
.rdata:00402026                 db  65h ; e
.rdata:00402027                 db 0E0h
.rdata:00402028                 db  80h ; €
.rdata:00402029                 db 0A0h
.rdata:0040202A                 db 0E0h
.rdata:0040202B                 db  81h
.rdata:0040202C                 db 0B4h
.rdata:0040202D                 db 0E0h
.rdata:0040202E                 db  81h
.rdata:0040202F                 db 0A8h
.rdata:00402030                 db 0C1h
.rdata:00402031                 db 0A5h
.rdata:00402032                 db  20h
.rdata:00402033                 db 0C1h
.rdata:00402034                 db 0A5h
.rdata:00402035                 db 0E0h
.rdata:00402036                 db  81h
.rdata:00402037                 db 0AEh
.rdata:00402038                 db  63h ; c
.rdata:00402039                 db 0C1h
.rdata:0040203A                 db 0AFh
.rdata:0040203B                 db 0E0h
.rdata:0040203C                 db  81h
.rdata:0040203D                 db 0A4h
.rdata:0040203E                 db 0F0h
.rdata:0040203F                 db  80h ; €
.rdata:00402040                 db  81h
.rdata:00402041                 db 0A9h
.rdata:00402042                 db  6Eh ; n
.rdata:00402043                 db 0C1h
.rdata:00402044                 db 0A7h
.rdata:00402045                 db 0C0h
.rdata:00402046                 db 0BAh
.rdata:00402047                 db  20h
.rdata:00402048                 db  49h ; I
.rdata:00402049                 db 0F0h
.rdata:0040204A                 db  80h ; €
.rdata:0040204B                 db  81h
.rdata:0040204C                 db  9Fh
.rdata:0040204D                 db 0C1h
.rdata:0040204E                 db 0A1h
.rdata:0040204F                 db 0C1h
.rdata:00402050                 db  9Fh
.rdata:00402051                 db 0C1h
.rdata:00402052                 db  8Dh
.rdata:00402053                 db 0E0h
.rdata:00402054                 db  81h
.rdata:00402055                 db  9Fh
.rdata:00402056                 db 0C1h
.rdata:00402057                 db 0B4h
.rdata:00402058                 db 0F0h
.rdata:00402059                 db  80h ; €
.rdata:0040205A                 db  81h
.rdata:0040205B                 db  9Fh
.rdata:0040205C                 db 0F0h
.rdata:0040205D                 db  80h ; €
.rdata:0040205E                 db  81h
.rdata:0040205F                 db 0A8h
.rdata:00402060                 db 0C1h
.rdata:00402061                 db  9Fh
.rdata:00402062                 db 0F0h
.rdata:00402063                 db  80h ; €
.rdata:00402064                 db  81h
.rdata:00402065                 db 0A5h
.rdata:00402066                 db 0E0h
.rdata:00402067                 db  81h
.rdata:00402068                 db  9Fh
.rdata:00402069                 db 0C1h
.rdata:0040206A                 db 0A5h
.rdata:0040206B                 db 0E0h
.rdata:0040206C                 db  81h
.rdata:0040206D                 db  9Fh
.rdata:0040206E                 db 0F0h
.rdata:0040206F                 db  80h ; €
.rdata:00402070                 db  81h
.rdata:00402071                 db 0AEh
.rdata:00402072                 db 0C1h
.rdata:00402073                 db  9Fh
.rdata:00402074                 db 0F0h
.rdata:00402075                 db  80h ; €
.rdata:00402076                 db  81h
.rdata:00402077                 db  83h
.rdata:00402078                 db 0C1h
.rdata:00402079                 db  9Fh
.rdata:0040207A                 db 0E0h
.rdata:0040207B                 db  81h
.rdata:0040207C                 db 0AFh
.rdata:0040207D                 db 0E0h
.rdata:0040207E                 db  81h
.rdata:0040207F                 db  9Fh
.rdata:00402080                 db 0C1h
.rdata:00402081                 db  84h
.rdata:00402082                 db  5Fh ; _
.rdata:00402083                 db 0E0h
.rdata:00402084                 db  81h
.rdata:00402085                 db 0A9h
.rdata:00402086                 db 0F0h
.rdata:00402087                 db  80h ; €
.rdata:00402088                 db  81h
.rdata:00402089                 db  9Fh
.rdata:0040208A                 db  6Eh ; n
.rdata:0040208B                 db 0E0h
.rdata:0040208C                 db  81h
.rdata:0040208D                 db  9Fh
.rdata:0040208E                 db 0E0h
.rdata:0040208F                 db  81h
.rdata:00402090                 db 0A7h
.rdata:00402091                 db 0E0h
.rdata:00402092                 db  81h
.rdata:00402093                 db  80h ; €
.rdata:00402094                 db 0F0h
.rdata:00402095                 db  80h ; €
.rdata:00402096                 db  81h
.rdata:00402097                 db 0A6h
.rdata:00402098                 db 0F0h
.rdata:00402099                 db  80h ; €
.rdata:0040209A                 db  81h
.rdata:0040209B                 db 0ACh
.rdata:0040209C                 db 0E0h
.rdata:0040209D                 db  81h
.rdata:0040209E                 db 0A1h
.rdata:0040209F                 db 0C1h
.rdata:004020A0                 db 0B2h
.rdata:004020A1                 db 0C1h
.rdata:004020A2                 db 0A5h
.rdata:004020A3                 db 0F0h
.rdata:004020A4                 db  80h ; €
.rdata:004020A5                 db  80h ; €
.rdata:004020A6                 db 0ADh
.rdata:004020A7                 db 0F0h
.rdata:004020A8                 db  80h ; €
.rdata:004020A9                 db  81h
.rdata:004020AA                 db 0AFh
.rdata:004020AB                 db  6Eh ; n
.rdata:004020AC                 db 0C0h
.rdata:004020AD                 db 0AEh
.rdata:004020AE                 db 0F0h
.rdata:004020AF                 db  80h ; €
.rdata:004020B0                 db  81h
.rdata:004020B1                 db 0A3h
.rdata:004020B2                 db  6Fh ; o
.rdata:004020B3                 db 0F0h
.rdata:004020B4                 db  80h ; €
.rdata:004020B5                 db  81h
.rdata:004020B6                 db 0ADh
.rdata:004020B7                 db    0
```

发现问题，这一串数据远不止28位，结合程序运行时的输出后面有个冒号

推测这串数据后半段就是flag，只是没有输出而已

于是找到函数sub_401160的汇编代码

```
.text:004011C0                 push    ebp
.text:004011C1                 mov     ebp, esp
.text:004011C3                 sub     esp, 84h
.text:004011C9                 push    1Ch
.text:004011CB                 push    offset unk_402008
.text:004011D0                 lea     eax, [ebp+Text]
.text:004011D6                 push    eax
.text:004011D7                 call    sub_401160
.text:004011DC                 add     esp, 0Ch
.text:004011DF                 mov     [ebp+var_4], eax
.text:004011E2                 mov     ecx, [ebp+var_4]
.text:004011E5                 mov     [ebp+ecx+Text], 0
.text:004011ED                 push    0               ; uType
.text:004011EF                 push    offset Caption  ; "Output"
.text:004011F4                 lea     edx, [ebp+Text]
.text:004011FA                 push    edx             ; lpText
.text:004011FB                 push    0               ; hWnd
.text:004011FD                 call    ds:MessageBoxA
.text:00401203                 xor     eax, eax
.text:00401205                 mov     esp, ebp
.text:00401207                 pop     ebp
.text:00401208                 retn    10h
```

把第四行push 1ch patch成一个大点的数，这里我写成push 5ch

然后apply一下，重新打开exe，大功告成！
![image](/upload/2022/02/image-21ac6bf4a041420eb7b2ff1f6ead6fae.png)

### 0×02 BJDCTF2020 easy

> 和上道题有异曲同工之处？

die查，结果PE32，进ida

直接定位main函数

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __time32_t Time; // [esp+10h] [ebp-3F0h] BYREF
  struct tm *v5; // [esp+3FCh] [ebp-4h]

  __main();
  time(&Time);
  v5 = localtime(&Time);
  puts("Can you find me?\n");
  system("pause");
  return 0;
}
```

各种time给我整蒙了，特意百度查了一下发现好像真没什么用

和上一题有异曲同工之妙?直接去翻参数列表

```
.text:00401725                 push    ebp
.text:00401726                 mov     ebp, esp
.text:00401728                 and     esp, 0FFFFFFF0h
.text:0040172B                 sub     esp, 400h
.text:00401731                 call    ___main
.text:00401736                 lea     eax, [esp+400h+var_3F0]
.text:0040173A                 mov     [esp+400h+Time], eax ; Time
.text:0040173D                 call    _time
.text:00401742                 lea     eax, [esp+400h+var_3F0]
.text:00401746                 mov     [esp+400h+Time], eax ; Time
.text:00401749                 call    _localtime
.text:0040174E                 mov     [esp+400h+var_4], eax
.text:00401755                 mov     [esp+400h+Time], offset Buffer ; "Can you find me?\n"
.text:0040175C                 call    _puts
.text:00401761                 mov     [esp+400h+Time], offset Command ; "pause"
.text:00401768                 call    _system
.text:0040176D                 mov     eax, 0
.text:00401772                 leave
.text:00401773                 retn
```

也没发现什么有用的，毫无头绪

翻函数列表的时候发现了问题，就是这个_ques函数，

```
int ques()
{
  int v0; // edx
  int result; // eax
  int v2[50]; // [esp+20h] [ebp-128h] BYREF
  int v3; // [esp+E8h] [ebp-60h]
  int v4[10]; // [esp+ECh] [ebp-5Ch]
  int j; // [esp+114h] [ebp-34h]
  __int64 v6; // [esp+118h] [ebp-30h]
  int v7; // [esp+124h] [ebp-24h]
  int v8; // [esp+128h] [ebp-20h]
  int i; // [esp+12Ch] [ebp-1Ch]

  v3 = 2147122737;
  v4[0] = 140540;
  v4[1] = -2008399303;
  v4[2] = 141956;
  v4[3] = 139457077;
  v4[4] = 262023;
  v4[5] = -2008923597;
  v4[6] = 143749;
  v4[7] = 2118271985;
  v4[8] = 143868;
  for ( i = 0; i <= 4; ++i )
  {
    memset(v2, 0, sizeof(v2));
    v8 = 0;
    v7 = 0;
    v0 = v4[2 * i];
    LODWORD(v6) = *(&v3 + 2 * i);
    HIDWORD(v6) = v0;
    while ( v6 > 0 )
    {
      v2[v8++] = v6 % 2;
      v6 /= 2i64;
    }
    for ( j = 50; j >= 0; --j )
    {
      if ( v2[j] )
      {
        if ( v2[j] == 1 )
        {
          putchar(42);
          ++v7;
        }
      }
      else
      {
        putchar(32);
        ++v7;
      }
      if ( !(v7 % 5) )
        putchar(32);
    }
    result = putchar(10);
  }
  return result;
}
```

从感觉上来说一般能看懂的都是有用的，然而按x查交叉引用的时候却显示没有地方调用它

于是盲猜前面没啥用的各种time函数就是让我patch的，搞他（我这里改了第11行

```
.text:00401725                 push    ebp
.text:00401726                 mov     ebp, esp
.text:00401728                 and     esp, 0FFFFFFF0h
.text:0040172B                 sub     esp, 400h
.text:00401731                 call    ___main
.text:00401736                 lea     eax, [esp+400h+var_3F0]
.text:0040173A                 mov     [esp+400h+Time], eax ; Time
.text:0040173D                 call    _time
.text:00401742                 lea     eax, [esp+400h+var_3F0]
.text:00401746                 mov     [esp+400h+Time], eax ; Time
.text:00401749                 call    _ques           ; Keypatch modified this from:
.text:00401749                                         ;   call _localtime
.text:0040174E                 mov     [esp+400h+var_4], eax
.text:00401755                 mov     [esp+400h+Time], offset Buffer ; "Can you find me?\n"
.text:0040175C                 call    _puts
.text:00401761                 mov     [esp+400h+Time], offset Command ; "pause"
.text:00401768                 call    _system
.text:0040176D                 mov     eax, 0
.text:00401772                 leave
.text:00401773                 retn
```

apply一下，然后重新运行exe，成功！

![image](/upload/2022/02/image-6b95eb4b15b74cf99825a9cc2ecb0b46.png)

# 第二周

2021-11-05  

## 0×00 从 CNSS 偷来的 SMC

> SMC是什么?

看完tips尝试一下

string窗口定位主函数

```
.text:00408ACE                 push    offset aPleaseInputYou ; "Please input your code(less than 30 cha"...
.text:00408AD3                 call    sub_404629
.text:00408AD8                 add     esp, 4
.text:00408ADB                 push    64h ; 'd'
.text:00408ADD                 push    offset unk_4DFEF8
.text:00408AE2                 push    offset aS       ; "%s"
.text:00408AE7                 call    sub_4023EC
.text:00408AEC                 add     esp, 0Ch
.text:00408AEF                 push    offset loc_408B06
.text:00408AF4                 push    138h
.text:00408AF9                 push    offset loc_408B06
.text:00408AFE                 call    sub_4022AC
.text:00408B03                 add     esp, 0Ch
```

定位问题函数sub_4022AC

```
int __cdecl sub_4088D0(int a1, int a2, int a3)
{
  int result; // eax
  int i; // [esp+D0h] [ebp-8h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(i + a3) = byte_4DF000 ^ *(_BYTE *)(i + a1);
  }
  return result;
}
```

idaPython 搞他

```python
from ida_bytes import *
for i in range(0x138):
    patch_byte(0x408B06+i,get_byte(0x408B06+i)^74)
```

按照步骤来到函数头CreatFonction，结果就出问题了

```
报错
.text:00408B19: The function has undefined instruction/data at the specified address.
Your request has been put in the autoanalysis queue.
```

开始以为是前面哪里做错了，又重复了几遍，一样的结果

请教RX大神发现问题

```
.text:00408B06                 mov     dword ptr [ebp-0Ch], 1
.text:00408B0D                 mov     dword ptr [ebp-8], 1
.text:00408B14                 push    4DFEF8h
.text:00408B14 ; ---------------------------------------------------------------------------
.text:00408B19                 db 0E8h
.text:00408B1A                 retn    0FF95h
.text:00408B1A ; ---------------------------------------------------------------------------
.text:00408B1D                 db 0FFh
```

这里ida识别错了

按c重新识别为code，一切正常了

重新CreateFunction接F5终于看到主函数

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  signed int j; // [esp+D4h] [ebp-3Ch]
  int i; // [esp+E0h] [ebp-30h]
  char v6; // [esp+EFh] [ebp-21h]
  signed int v7; // [esp+F8h] [ebp-18h]
  int v8; // [esp+104h] [ebp-Ch]
  int v9; // [esp+108h] [ebp-8h]

  sub_404629("Please input your code(less than 30 characters): ");
  sub_4023EC("%s", Str);
  sub_4022AC((int)&loc_408B06, 312, (int)&loc_408B06);
  v8 = 1;
  v9 = 1;
  v7 = j__strlen(Str);
  v6 = 0;
  if ( v7 == 23 )
  {
    for ( i = 0; i < 23; ++i )
    {
      switch ( Str[i] )
      {
        case 'a':
          --v9;
          break;
        case 'd':
          ++v9;
          break;
        case 's':
          ++v8;
          break;
        case 'w':
          --v8;
          break;
        default:
          break;
      }
      if ( aSE[8 * v8 + v9] == 35 )
        break;
      if ( aSE[8 * v8 + v9] == 69 )
      {
        v6 = 1;
        break;
      }
    }
  }
  if ( v6 )
  {
    for ( j = 0; j < v7; ++j )
      byte_4DF04C[j] ^= Str[j];
    sub_404629("%s\n");
  }
  j__system("pause");
  return 0;
}
```

经典地图题,aSE数组存地图，加回车得地图

```
########
#S #   #
##   # #
#####  #
#     ##
# ####E#
#      #
########
```

w s a d十分人性化，好评

第一次用py写脚本

```python
key = "dsddwddssasaaaassdddddw"
magic = [39, 61, 55, 55, 12, 33, 5, 70, 10, 62, 32, 44, 34, 62,71, 44, 18, 59, 41, 5, 86, 1, 10]
for i in range(0,23):
    print( chr( magic[i] ^ ord(key[i]) ), end="")
# CNSS{Ea5y_SMC_&_a_Ma2e}
```

## 0×01 ByteCTF 2020 AWD

> TikTokAdmin 简单花指令

题目劝退，学习了一波花指令是啥再来做题

根据题目，在string窗口查找Delete，找到了发生错误的部分

```
.text:00000000000080D4 loc_80D4:                               ; CODE XREF: .text:000000000000805C↑j
.text:00000000000080D4                 lea     rsi, aWeNeedToReconf ; "We need to reconfirm the authority!"
.text:00000000000080DB                 lea     rdi, _ZSt4cout  ; std::cout
.text:00000000000080E2                 call    __ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
.text:00000000000080E7                 mov     rdx, rax
.text:00000000000080EA                 mov     rax, cs:_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__ptr
.text:00000000000080F1                 mov     rsi, rax
.text:00000000000080F4                 mov     rdi, rdx
.text:00000000000080F7                 call    __ZNSolsEPFRSoS_E ; std::ostream::operator<<(std::ostream & (*)(std::ostream &))
.text:00000000000080FC                 lea     rsi, aPleaseInputThe ; "Please input the super root's password:"...
.text:0000000000008103                 mov     rdi, rax
.text:0000000000008106                 call    __ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*)
.text:000000000000810B                 lea     rax, [rbp-90h]
.text:0000000000008112                 mov     rsi, rax
.text:0000000000008115                 lea     rdi, _ZSt3cin   ; std::cin
.text:000000000000811C                 call    __ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE ; std::operator>><char>(std::istream &,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> &)
.text:0000000000008121                 jz      short near ptr loc_8125+1
.text:0000000000008123                 jnz     short near ptr loc_8125+1
.text:0000000000008125
.text:0000000000008125 loc_8125:                               ; CODE XREF: .text:0000000000008121↑j
.text:0000000000008125                                         ; .text:0000000000008123↑j
.text:0000000000008125                 call    near ptr 70860E72h
.text:0000000000008125 ; ---------------------------------------------------------------------------
.text:000000000000812A                 dw 0FFFFh, 48FFh, 0C789h
.text:0000000000008130                 dq 0C38948FFFFB56BE8h, 48FFFFFF70858D48h, 48FFFFB489E8C789h
.text:0000000000008130                 dq 8948B0458D48C189h, 0E8C78948CE8948DAh, 0B0458D48FFFFB584h
.text:0000000000008130                 dq 358D480000000DBAh, 0E8C7894800007B1Dh, 840FC085FFFFB48Ch
.text:0000000000008130                 dq 14358D48000000F6h, 0DEF63D8D4800007Bh, 48FFFFB5E1E80000h
.text:0000000000008130                 dq 8948B0458D48C289h, 0FFB5CFE8D78948C6h, 7AFD358D48FFh
```

问题出在了jz（为0跳转）和jnz（不为0跳转）同时存在，并插入了0xE8（call的机器码）使ida识别出错

解决方法先把call按u改成未定义,效果如图

```
.text:0000000000008125                 db 0E8h
.text:0000000000008126 unk_8126        db  48h ; H             ; CODE XREF: .text:0000000000008121↑j
.text:0000000000008126                                         ; .text:0000000000008123↑j
.text:0000000000008127                 db  8Dh
.text:0000000000008128                 db  85h
.text:0000000000008129                 db  70h ; p
.text:000000000000812A                 dw 0FFFFh, 48FFh, 0C789h
```

然后把0xE8 patch成nop（空），其他数据按c重新分析成代码

```
.text:0000000000008123 ; ---------------------------------------------------------------------------
.text:0000000000008125                 db 90h                  ; Keypatch modified this from:
.text:0000000000008125                                         ;   db 0E8h
.text:0000000000008125                                         ; Keypatch padded NOP to next boundary: 1 bytes
.text:0000000000008126 ; ---------------------------------------------------------------------------
.text:0000000000008126
.text:0000000000008126 loc_8126:                               ; CODE XREF: .text:0000000000008121↑j
.text:0000000000008126                                         ; .text:0000000000008123↑j
.text:0000000000008126                 lea     rax, [rbp-90h]
.text:000000000000812D                 mov     rdi, rax
.text:0000000000008130                 call    __ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(void)
.text:0000000000008135                 mov     rbx, rax
.text:0000000000008138                 lea     rax, [rbp-90h]
.text:000000000000813F                 mov     rdi, rax
.text:0000000000008142                 call    __ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv ; std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(void)
.text:0000000000008147                 mov     rcx, rax
.text:000000000000814A                 lea     rax, [rbp-50h]
.text:000000000000814E                 mov     rdx, rbx
.text:0000000000008151                 mov     rsi, rcx
```

然后发现下面还有一个一样的错误，相同办法解决

最后来到函数头Create Function，

完事后到虚拟机上看一眼

```
dx3906@ubuntu:~/Desktop$ '/home/dx3906/pwn.so' 
                            '--'''   '               
                            l__++??_''               
                            ;??JCLCQj(               
                            ;?{BB%@@p0,^'            
                            I-{&B@@B@q+'-            
                            ;?}8@%$@@Bb;- '          
                            ;?}8@$$@$$B&r^-''        
                            ;?}%@@@B$$B@B8O?~:-      
                           ';?}8@B@@$@$$$$$BBpO{     
                  '    ''' ';?}8@B@BBB@@@@@B@pw(     
                  ^l+?][I'  ;?}8@@%MwOa%@@$@Bdq1     
             '',?-_?_)uZ0c~';_}%@@@MqJ^IcOwmbqq)     
          ''^:?_+]w&B@@@am( ;-[8@@@MqJ^   '">[|i     
           ^<--}MB@@@@@@am( ;-[8@$$WqJ-' '''  ''     
          '?]+C%@@$@8#aobq)':_[%@@@WqU-'             
        '-i]}m@BB%*qd0Q0cU}^I+[%@@@MwU-              
        '^[?n%B@@aqwL:-^'-"-I+[%@@@MwU-              
         ^-_#@$$%wpx-      ';+[B@@@MwU-              
         ^]-B$@@%pq"''     '<_{8@@BMmC-              
        -^??8$$@@kO,      '---1%@$@aqU-              
        '->-#@$@BBo>'''-'^:?-?h$$$8mwt               
          '+YBB@@$8&Q-!_]+_[]*$BBBqwqI               
         ''"[&B@@$@@%8WJ/npMB%B@%qwq}                
           '';M@@@@@$@@B@@@@@@@MmpO]-'               
            '^;_88@@@@B@B@$B&oqqqC" ^'               
               -l}mbo&8&&oqmdwZQ:-'                  
                 -^~nOwqpZz[I"''                     
                  '   ''''-'''                       
    ████████╗██╗██╗  ██╗████████╗ ██████╗ ██╗  ██╗
    ╚══██╔══╝██║██║ ██╔╝╚══██╔══╝██╔═══██╗██║ ██╔╝
       ██║   ██║█████╔╝    ██║   ██║   ██║█████╔╝ 
       ██║   ██║██╔═██╗    ██║   ██║   ██║██╔═██╗ 
       ██║   ██║██║  ██╗   ██║   ╚██████╔╝██║  ██╗
       ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
This is the background management system for TikTok.
PassWord:
```

还挺不错，可惜要password

原本是想找一找的，结果看到代码发现我想多了，就先到这吧

## 0×02 BJDCTF 2020 老八的小汉堡

游戏真不错，但题实话说属于没题解不会做系列（

下了个dnspy，根据题解打开Data/Managed目录下的Assembly-CSharp.dll

搜索字符串“美汁汁”定位主函数
![image](/upload/2022/02/image-0516a67c9995408289e0b1bd19c5f1ca.png)

```
public class ButtonSpawnFruit : MonoBehaviour
{
    // Token: 0x0600000A RID: 10 RVA: 0x00002110 File Offset: 0x00000310
    public static string Md5(string str)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(str);
        byte[] array = MD5.Create().ComputeHash(bytes);
        StringBuilder stringBuilder = new StringBuilder();
        foreach (byte b in array)
        {
            stringBuilder.Append(b.ToString("X2"));
        }
        return stringBuilder.ToString().Substring(0, 20);
    }

    // Token: 0x0600000B RID: 11 RVA: 0x00002170 File Offset: 0x00000370
    public static string Sha1(string str)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(str);
        byte[] array = SHA1.Create().ComputeHash(bytes);
        StringBuilder stringBuilder = new StringBuilder();
        foreach (byte b in array)
        {
            stringBuilder.Append(b.ToString("X2"));
        }
        return stringBuilder.ToString();
    }

    // Token: 0x0600000C RID: 12 RVA: 0x000021C8 File Offset: 0x000003C8
    public void Spawn()
    {
        FruitSpawner component = GameObject.FindWithTag("GameController").GetComponent<FruitSpawner>();
        if (component)
        {
            if (this.audioSources.Length != 0)
            {
                this.audioSources[Random.Range(0, this.audioSources.Length)].Play();
            }
            component.Spawn(this.toSpawn);
            string name = this.toSpawn.name;
            if (name == "汉堡底" && Init.spawnCount == 0)
            {
                Init.secret += 997;
            }
            else if (name == "鸭屁股")
            {
                Init.secret -= 127;
            }
            else if (name == "胡罗贝")
            {
                Init.secret *= 3;
            }
            else if (name == "臭豆腐")
            {
                Init.secret ^= 18;
            }
            else if (name == "俘虏")
            {
                Init.secret += 29;
            }
            else if (name == "白拆")
            {
                Init.secret -= 47;
            }
            else if (name == "美汁汁")
            {
                Init.secret *= 5;
            }
            else if (name == "柠檬")
            {
                Init.secret ^= 87;
            }
            else if (name == "汉堡顶" && Init.spawnCount == 5)
            {
                Init.secret ^= 127;
                string str = Init.secret.ToString();
                if (ButtonSpawnFruit.Sha1(str) == "DD01903921EA24941C26A48F2CEC24E0BB0E8CC7")
                {
                    this.result = "BJDCTF{" + ButtonSpawnFruit.Md5(str) + "}";
                    Debug.Log(this.result);
                }
            }
            Init.spawnCount++;
            Debug.Log(Init.secret);
            Debug.Log(Init.spawnCount);
        }
    }
```

基本思路是已知sha1(str)==DD01903921EA24941C26A48F2CEC24E0BB0E8CC7,求md5(str)

还是根据题解上cmd5.com得str==1001

然后md5加密，注意这一句，取加密后的0-20（不包括20）即前20位（前人之鉴属于是 

```
return stringBuilder.ToString().Substring(0, 20)
```

ipython跑一遍得flag

```
In [1]: from hashlib import md5
In [2]: a=md5()
In [3]: a.update(b"1001")
In [4]: print("BJDCTF{"+a.hexdigest()[:20]+"}")
BJDCTF{b8c37e33defde51cf91e}
```

总结：这周题真是给我开眼界的（

# 第一周

2021-10-31

写在前面：

- 新人第一次发帖，多多指教

- 长篇幅警告，写得比较繁琐

- 主要记录自己的做题过程，当然还有水水水

## 0x00 DMCTF 2020 re1

> 来点简单的算法甜点

解压后只有一个exe文件，先运行看看

提示输入flag，乱输提示 wrong flag！

```
flag:134123421
wrong flag!
请按任意键继续. . .
```

拖进die，无壳，进ida

看不懂汇编，直接F5，进main_0函数

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  char Str; // [esp+DCh] [ebp-40h] BYREF
  char v5[54]; // [esp+DDh] [ebp-3Fh] BYREF

  __CheckForDebuggerJustMyCode(&unk_5E0029);
  Str = 0;
  j__memset(v5, 0, sizeof(v5));
  sub_485257("flag:");
  sub_484CF3(&dword_5DD268, &Str);
  if ( sub_485D1A(&Str) )
    sub_4849EC(&Str);
  else
    sub_485257("wrong flag!\n");
  sub_488209("pause");
  return 0;
}
```

发现有用的主要在if else

先进if判断条件函数sub_485D1A

```c
BOOL __cdecl sub_49BE80(char *Str)
{
  __CheckForDebuggerJustMyCode(&unk_5E0029);
  return j__strlen(Str) == 20;
}
```

第一行看不懂也感觉没用，直接忽略，第二行限制输入为20个字符

回来再进if下函数sub_4849EC

```
int __cdecl sub_49AE10(char *Str1)
{
  int result; // eax
  int i; // [esp+D0h] [ebp-2Ch]
  char Str2[28]; // [esp+DCh] [ebp-20h] BYREF

  __CheckForDebuggerJustMyCode(&unk_5E0029);
  strcpy(Str2, "fmesh{umkc_vlrn_glh}");
  for ( i = 0; i <= 19; ++i )
  {
    if ( Str1[i] < 97 || Str1[i] >= 108 )
    {
      if ( Str1[i] > 110 && Str1[i] <= 122 )
        --Str1[i];
    }
    else
    {
      Str1[i] += 2;
    }
  }
  if ( !j__strcmp(Str1, Str2) )
    result = sub_485257("congratulations!\n");
  else
    result = sub_485257("wrong flag!\n");
  return result;
}
```

发现是个简单的加密

加改成减，减改成加，逆写得到flag，粘个代码

```c
#include<cstdio>
char Str1[]="fmesh{umkc_vlrn_glh}";
int main(){
    for(int i=0;i<=19;i++){
        if ( Str1[i] < 97 || Str1[i] >= 108 ){
          if ( Str1[i] > 110 && Str1[i] <= 122 )
            Str1[i]++;
        }
        else{
          Str1[i] -= 2;
        }
    }
    puts(Str1);
}
//flag:dmctf{vmia_wlsn_elf}
```

然而据说这题多解，咱也不知道，咱也不敢问

### 0x01 DMCTF 2020 re4

> “最短路径”

直接打开exe，输入key闪退差评

cmd打开

```
C:\Users\DX3906>D:\DX3906\下载\12345\12345.exe
key:1234123
failed.
failed.
failed.
failed.
failed.
failed.
failed.
failed.
```

8个failed直呼好狠

die查壳：无，拖进ida

直接F5，找不到主函数

```c
void __noreturn start()
{
  _set_app_type(_crt_console_app);
  sub_4011B0();
}
```

打开string窗口

```
.rdata:00405000    00000013    C    libgcc_s_dw2-1.dll
.rdata:00405013    00000016    C    __register_frame_info
.rdata:00405029    00000018    C    __deregister_frame_info
.rdata:00405041    0000000E    C    libgcj-16.dll
.rdata:0040504F    00000014    C    _Jv_RegisterClasses
.rdata:0040506A    00000008    C    failed.
.rdata:00405072    0000000A    C    flag{%s}\n
.rdata:00405080    00000018    C    Mingw runtime failure:\n
.rdata:00405098    00000031    C      VirtualQuery failed for %d bytes at address %p
.rdata:004050CC    00000032    C      Unknown pseudo relocation protocol version %d.\n
.rdata:00405100    0000002A    C      Unknown pseudo relocation bit size %d.\n
```

映入眼帘就是failed

点他——

`rdata:0040506A Buffer          db 'failed.',0          ; DATA XREF: sub_401460:loc_4015A3↑o`

发现函数sub_401460，点他弹出来汇编，再F5，终于进了真的主函数

```c
int sub_401460()
{
  int v0; // eax
  char Buffer[51]; // [esp+3Dh] [ebp-43h] BYREF
  int v3; // [esp+70h] [ebp-10h]
  int i; // [esp+74h] [ebp-Ch]
  int v5; // [esp+78h] [ebp-8h]
  int v6; // [esp+7Ch] [ebp-4h]

  sub_401BD0();
  printf("key:");
  fgets(Buffer, 50, (FILE *)iob[0]._ptr);
  v3 = strlen(Buffer);
  if ( Buffer[v3 - 1] == 10 )
    Buffer[v3 - 1] = 0;
  --v3;
  v6 = 0;
  v5 = 0;
  for ( i = 0; i < v3; ++i )
  {
    v0 = Buffer[i];
    if ( v0 == 0x31 )
    {
      --v5;
    }
    else if ( v0 > 49 )
    {
      if ( v0 == 50 )
      {
        ++v6;
      }
      else
      {
        if ( v0 != 51 )
        {
LABEL_16:
          puts("failed.");
          goto LABEL_17;
        }
        --v6;
      }
    }
    else
    {
      if ( v0 != 48 )
        goto LABEL_16;
      ++v5;
    }
LABEL_17:
    if ( !byte_404020[10 * v6 + v5] || v6 < 0 || v5 < 0 || v6 > 9 || v5 > 9 )
      puts("failed.");
  }
  if ( v6 == 9 && v5 == 9 )
    printf("flag{%s}\n", Buffer);
  return 0;
}
```

观察LABEL_17中if的判断条件，咋看咋像迷宫题，v6表示行，v5表示列，0-9共10行10列

进数组byte_404020，数据都是0和1，更加确信迷宫

```
.data:00404020 byte_404020     db 1                    ; DATA XREF: sub_401460+164↑r
.data:00404021                 db    0
.data:00404022                 db    0
.data:00404023                 db    0
.data:00404024                 db    0
.data:00404025                 db    1
.data:00404026                 db    1
.data:00404027                 db    0
.data:00404028                 db    0
.data:00404029                 db    0
.data:0040402A                 db    1
.data:0040402B                 db    1
.data:0040402C                 db    0
.data:0040402D                 db    0
.data:0040402E                 db    0
.data:0040402F                 db    1
.data:00404030                 db    1
.data:00404031                 db    1
.data:00404032                 db    0
```

但，这要我一个个扣出来？？

右键选择Array

然后把size改成100（10行10列共100个数

舒服~

```
.data:00404020 byte_404020     db 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1; 0
.data:00404020                                         ; DATA XREF: sub_401460+164↑r
.data:00404020                 db 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1; 18
.data:00404020                 db 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0; 36
.data:00404020                 db 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0; 54
.data:00404020                 db 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1; 72
.data:00404020                 db 0, 0, 0, 0, 0, 0, 0, 0, 0, 1; 90
```

复制粘贴出迷宫

```
1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 
1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 
0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 
0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 
0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 
0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 
0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 
0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 
0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
```

回头再看函数

```
for ( i = 0; i < v3; ++i )
  {
    v0 = Buffer[i];
    if ( v0 == 0x31 )
    {
      --v5;
    }
    else if ( v0 > 49 )
    {
      if ( v0 == 50 )
      {
        ++v6;
      }
      else
      {
        if ( v0 != 51 )
        {
LABEL_16:
          puts("failed.");
          goto LABEL_17;
        }
        --v6;
      }
    }
    else
    {
      if ( v0 != 48 )
        goto LABEL_16;
      ++v5;
    }
LABEL_17:
    if ( !byte_404020[10 * v6 + v5] || v6 < 0 || v5 < 0 || v6 > 9 || v5 > 9 )
      puts("failed.");
  }
```

易得

```
0    ++v5    right
1    --v5    left
2    ++v6    down
3    --v6    up
```

手动走迷宫得 key:20220002033330202222202202

回cmd运行得flag

```
key:20220002033330202222202202
flag{20220002033330202222202202}
```

## 0x02 GWCTF 2019 xxor

> 快乐的解方程题目

解压打开发现不是exe，无法打开直接拖die

发现是elf64（linux可执行文件），马上去开虚拟机

ubuntu里先运行一下

```
dx3906@ubuntu:~/Desktop$ '/home/dx3906/attachment' 
Let us play a game?
you have six chances to input
Come on!
input: 1231212
input: 3
input: 12
input: 3
input: 12
input: 3
Wrong!
NO NO NO~
```

发现题目需要输入六次，拖ida F5

在左边Functions Window找到了main函数，竟然是真的

```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+8h] [rbp-68h]
  int j; // [rsp+Ch] [rbp-64h]
  __int64 v6[6]; // [rsp+10h] [rbp-60h] BYREF
  __int64 v7[6]; // [rsp+40h] [rbp-30h] BYREF

  v7[5] = __readfsqword(0x28u);
  puts("Let us play a game?");
  puts("you have six chances to input");
  puts("Come on!");
  v6[0] = 0LL;
  v6[1] = 0LL;
  v6[2] = 0LL;
  v6[3] = 0LL;
  v6[4] = 0LL;
  for ( i = 0; i <= 5; ++i )
  {
    printf("%s", "input: ");
    __isoc99_scanf("%d", (char *)v6 + 4 * i);
  }
  v7[0] = 0LL;
  v7[1] = 0LL;
  v7[2] = 0LL;
  v7[3] = 0LL;
  v7[4] = 0LL;
  for ( j = 0; j <= 2; ++j )
  {
    dword_601078 = v6[j];
    dword_60107C = HIDWORD(v6[j]);
    sub_400686(&dword_601078, &unk_601060);
    LODWORD(v7[j]) = dword_601078;
    HIDWORD(v7[j]) = dword_60107C;
  }
  if ( (unsigned int)sub_400770(v7) != 1 )
  {
    puts("NO NO NO~ ");
    exit(0);
  }
  puts("Congratulation!\n");
  puts("You seccess half\n");
  puts("Do not forget to change input to hex and combine~\n");
  puts("ByeBye");
  return 0LL;
}
```

倒着看，先进if里面的判断函数sub_400770(v7)

```
__int64 __fastcall sub_400770(_DWORD *a1)
{
  __int64 result; // rax

  if ( a1[2] - a1[3] == 0x84A236FFLL
    && a1[3] + a1[4] == 0xFA6CB703LL
    && a1[2] - a1[4] == 0x42D731A8LL
    && *a1 == 0xDF48EF7E
    && a1[5] == 0x84F30420
    && a1[1] == 0x20CAACF4 )
  {
    puts("good!");
    result = 1LL;
  }
  else
  {
    puts("Wrong!");
    result = 0LL;
  }
  return result;
}
```

果然如题目解方程，z3搞它

```python
from z3 import *
a = Int('a')
b = Int('b')
c = Int('c')
d = Int('d')
e = Int('e')
f = Int('f')
s = Solver()
s.add(a == 0xDF48EF7E)
s.add(b == 0x20CAACF4)
s.add(f == 0x84F30420)
s.add(c-d == 0x84A236FF)
s.add(d+e == 0xFA6CB703)
s.add(c-e == 0x42D731A8)
print(s.check())
print(s.model())
```

a-f表示a1的0-5，z3里不会定义数组，干脆用字母，会的佬教一下孩子

得到结果

```
sat
[c = 3774025685,
 d = 1548802262,
 e = 2652626477,
 f = 2230518816,
 b = 550153460,
 a = 3746099070]
```

但这还没完（要是光解方程可能也做不了第三题

解出来的是加密后的input，加密算法如下

```
  for ( j = 0; j <= 2; ++j )
  {
    dword_601078 = v6[j];
    dword_60107C = HIDWORD(v6[j]);
    sub_400686(&dword_601078, &unk_601060);
    LODWORD(v7[j]) = dword_601078;
    HIDWORD(v7[j]) = dword_60107C;
  }
```

基本是把高四字节（HIDWORD）和低四字节（LODWORD）分开一顿操作，进函数sub_400686

```
__int64 __fastcall sub_400686(unsigned int *a1, _DWORD *a2)
{
  __int64 result; // rax
  unsigned int v3; // [rsp+1Ch] [rbp-24h]
  unsigned int v4; // [rsp+20h] [rbp-20h]
  int v5; // [rsp+24h] [rbp-1Ch]
  unsigned int i; // [rsp+28h] [rbp-18h]

  v3 = *a1;
  v4 = a1[1];
  v5 = 0;
  for ( i = 0; i <= 0x3F; ++i )
  {
    v5 += 0x458BCD42;
    v3 += (v4 + v5 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
    v4 += (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
  }
  *a1 = v3;
  result = v4;
  a1[1] = v4;
  return result;
}
```

感觉好像我的二面题，tea加密？

变量只有v3，v4，且求v3时v4已知，求v4时v3已知

结论：可逆，难点在于各种数据类型容易把自己搞晕

注意主函数input格式控制为%d，故用int存flag

```
__isoc99_scanf("%d", (char *)v6 + 4 * i);
```

完整代码

```c
#include<cstdio>
unsigned int flag[100],a1[]={3746099070,550153460,3774025685,1548802262,2652626477,2230518816};
unsigned long long a2[10];
unsigned int key[5]={2,2,3,4};
int v5;
int main(){
    for(int i=0;i<3;i++){
        a2[i]=*((unsigned long long*)a1+i);
    }
    for(int i=0;i<3;i++){
        unsigned int xl=*((unsigned int*)&a2[i]);//低位 
        unsigned int xh=*((unsigned int*)&a2[i]+1);//高位 
        for(int j=0x3F;j>=0;j--){
            v5=(j+1)*0x458BCD42;
            xh-=(xl+v5+20)^((xl<<6)+key[2])^((xl>>9)+key[3])^0x10;
            xl-=(xh+v5+11)^((xh<<6)+key[0])^((xh>>9)+key[1])^0x20;
        }
        flag[2*i]=xl;
        flag[2*i+1]=xh;
    }
    for(int i=0;i<6;i++){
        printf("%d\n",flag[i]);
    }
}
```

输出6个数字

```
6712417
6781810
6643561
7561063
7497057
7610749
```

回 Ubuntu input

```
dx3906@ubuntu:~/Desktop$ '/home/dx3906/attachment' 
Let us play a game?
you have six chances to input
Come on!
input: 6712417
input: 6781810
input: 6643561
input: 7561063
input: 7497057
input: 7610749
good!
Congratulation!
You seccess half
Do not forget to change input to hex and combine~
ByeBye
```

成功了，但还没有完全成功

hex？？？百度先

偷懒得flag，真香

![image](/upload/2022/02/image-44c372607bfe4868b41323a4c74e405f.png)

当然还是要认真学一学（

[Base64与Hex编码](https://zhuanlan.zhihu.com/p/344477237 "Base64与Hex编码")

最后，手写解码奉上(使用上一段代码的flag数组)

```
bool f=0;
int t,cnt=0,ans[10];
for(int i=0;i<6;i++){
    cnt=0;
    while(flag[i]){
        if(!f){
            t=flag[i]%16;
            flag[i]/=16;
            f=1;
        }
        if(f){
            t+=flag[i]%16<<4;
            flag[i]/=16;
            ans[++cnt]=t;
            f=0;
        }
    }
    for(int j=cnt;j>=1;j--){
        printf("%c",ans[j]);
    }
}
```

