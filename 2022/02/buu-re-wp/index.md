# buu re wp


# buuoj re wp

## CrackRTF

- ida定位main函数F5

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  DWORD v3; // eax
  DWORD v4; // eax
  char Str[260]; // [esp+4Ch] [ebp-310h] BYREF
  int v7; // [esp+150h] [ebp-20Ch]
  char String1[260]; // [esp+154h] [ebp-208h] BYREF
  char Destination[260]; // [esp+258h] [ebp-104h] BYREF

  memset(Destination, 0, sizeof(Destination));
  memset(String1, 0, sizeof(String1));
  v7 = 0;
  printf("pls input the first passwd(1): ");
  scanf("%s", Destination);
  if ( strlen(Destination) != 6 )
  {
    printf("Must be 6 characters!\n");
    ExitProcess(0);
  }
  v7 = atoi(Destination);                       // atoi是把字符串形式的数字转化为数字，可确定6位数字密码，即可爆破
  if ( v7 < 100000 )
    ExitProcess(0);
  strcat(Destination, "@DBApp");
  v3 = strlen(Destination);
  sub_40100A((BYTE *)Destination, v3, String1); // 动调测试可知为sha1加密，爆破拿前6位密码
  if ( !_strcmpi(String1, "6E32D0943418C2C33385BC35A1470250DD8923A9") )
  {
    printf("continue...\n\n");
    printf("pls input the first passwd(2): ");
    memset(Str, 0, sizeof(Str));
    scanf("%s", Str);
    if ( strlen(Str) != 6 )
    {
      printf("Must be 6 characters!\n");
      ExitProcess(0);
    }
    strcat(Str, Destination);
    memset(String1, 0, sizeof(String1));
    v4 = strlen(Str);
    sub_401019((BYTE *)Str, v4, String1);       // 动调测试得知为md5,但爆破6位全字符不现实，密码无法从这获得
    if ( !_strcmpi("27019e688a4e62a649fd99cadaafdb4e", String1) )
    {
      if ( !(unsigned __int8)sub_40100F(Str) )
      {
        printf("Error!!\n");
        ExitProcess(0);
      }
      printf("bye ~~\n");
    }
  }
  return 0;
}
```

- 题目需要输入两次密码，分别经加密函数后与已知字符串比较

- 第一次加密
  
  - 加密前`atoi`函数作用是把string形式的数字转化为int类型的数字，提示前6位密码为6位数字
  
  - `sub_40100A`是第一个加密函数，内部调用了windows库的加密函数，可以通过查看windows官方文档辨别参数得知为sha1加密，我这里是用动调对比在线加密网站加密结果确定加密算法为sha1

```c
//sub_40100A内部嵌套sub_401230函数
int __cdecl sub_401230(BYTE *pbData, DWORD dwDataLen, LPSTR lpString1)
{
  int result; // eax
  DWORD i; // [esp+4Ch] [ebp-28h]
  CHAR String2[4]; // [esp+50h] [ebp-24h] BYREF
  BYTE v6[20]; // [esp+54h] [ebp-20h] BYREF
  DWORD pdwDataLen; // [esp+68h] [ebp-Ch] BYREF
  HCRYPTHASH phHash; // [esp+6Ch] [ebp-8h] BYREF
  HCRYPTPROV phProv; // [esp+70h] [ebp-4h] BYREF

  if ( !CryptAcquireContextA(&phProv, 0, 0, 1u, 0xF0000000) )
    return 0;
  if ( CryptCreateHash(phProv, 0x8004u, 0, 0, &phHash) )
  {
    if ( CryptHashData(phHash, pbData, dwDataLen, 0) )
    {
      CryptGetHashParam(phHash, 2u, v6, &pdwDataLen, 0);
      *lpString1 = 0;
      for ( i = 0; i < pdwDataLen; ++i )
      {
        wsprintfA(String2, "%02X", v6[i]);
        lstrcatA(lpString1, String2);
      }
      CryptDestroyHash(phHash);
      CryptReleaseContext(phProv, 0);
      result = 1;
    }
    else
    {
      CryptDestroyHash(phHash);
      CryptReleaseContext(phProv, 0);
      result = 0;
    }
  }
  else
  {
    CryptReleaseContext(phProv, 0);
    result = 0;
  }
  return result;
}
```

- sha1是单向散列函数，没法逆，幸好是6位数字，直接爆破拿到密码`123321`

```py
import hashlib

for i in range(100000,999999):
    sha1 = hashlib.sha1()
    inp = str(i) + "@DBApp"
    sha1.update(inp.encode("utf-8"))
    if sha1.hexdigest().lower() == "6E32D0943418C2C33385BC35A1470250DD8923A9".lower():
        print(i)
# output：123321
```

- 同理第二个加密算法可知为md5，但没有限定为数字，试了试6位数字爆破没有结果，6位全字符爆破不现实

- 继续往下看`sub_40100F`传参调用了输入的`str`

```c
//sub_40100F中嵌套了sub_4014D0
char __cdecl sub_4014D0(LPCSTR lpString)
{
  LPCVOID lpBuffer; // [esp+50h] [ebp-1Ch]
  DWORD NumberOfBytesWritten; // [esp+58h] [ebp-14h] BYREF
  DWORD nNumberOfBytesToWrite; // [esp+5Ch] [ebp-10h]
  HGLOBAL hResData; // [esp+60h] [ebp-Ch]
  HRSRC hResInfo; // [esp+64h] [ebp-8h]
  HANDLE hFile; // [esp+68h] [ebp-4h]

  hFile = 0;
  hResData = 0;
  nNumberOfBytesToWrite = 0;
  NumberOfBytesWritten = 0;
  hResInfo = FindResourceA(0, (LPCSTR)0x65, "AAA");// Resource-Hacker看资源
  if ( !hResInfo )
    return 0;
  nNumberOfBytesToWrite = SizeofResource(0, hResInfo);
  hResData = LoadResource(0, hResInfo);
  if ( !hResData )
    return 0;
  lpBuffer = LockResource(hResData);
  sub_401005(lpString, (int)lpBuffer, nNumberOfBytesToWrite);// 和lpString异或得到lpbuffer
  hFile = CreateFileA("dbapp.rtf", 0x10000000u, 0, 0, 2u, 0x80u, 0);
  if ( hFile == (HANDLE)-1 )
    return 0;
  if ( !WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0) )
    return 0;
  CloseHandle(hFile);
  return 1;
}
```

- sub_401005函数内部进行逐位异或

```c
//sub_401005内部嵌套sub_401420
void __cdecl sub_401420(LPCSTR lpString, char *_8, int _C)
{
  unsigned int i; // [esp+4Ch] [ebp-Ch]
  unsigned int v4; // [esp+54h] [ebp-4h]

  v4 = lstrlenA(lpString);
  for ( i = 0; i < _C; ++i )
    _8[i] ^= lpString[i % v4];                  // 根据RTF文件头解出6位密码
}
```

- _8数组初值为资源AAA中的值，可用ResourceHacker查看资源得到
  ![Screenshot_20220222_225157.png](/upload/2022/02/Screenshot_20220222_225157-7f0d77ff45854a25b810696ea313d939.png)

- lpString的值可由RTF文件头得到`7B 5C 72 74 66`，但这只有5位，翻看大佬wp好像第6位默认是0x31？但这一点翻了会google未找到依据

- 我这里是先用异或解出前5位，然后结合md5爆破出最后一位，虽然麻烦，但确保正确

```py
import hashlib
RtfHead = [0x7B,0x5C,0x72,0x74,0x66]
AAA = [0x05,0x7d,0x41,0x15,0x26]
key = ""
for i in range(5):
    key += chr(RtfHead[i] ^ AAA[i])

for i in range(32,127):
    md5 = hashlib.md5()
    inp = key + chr(i) + "123321@DBApp"
    md5.update(inp.encode("utf-8"))
    if md5.hexdigest().lower() == "27019e688a4e62a649fd99cadaafdb4e":
        print(key + chr(i))
#output：~!3a@0
```

运行程序输入两次密码，会生成`dbapp.rtf`文件，打开即可看到flag`Flag{N0_M0re_Free_Bugs}`

## [2019红帽杯]easyRE

- 参考[官方wp](https://www.cnblogs.com/Mayfly-nymph/p/11869959.html#easyREhttps://www.cnblogs.com/Mayfly-nymph/p/11869959.html#easyREhttps://www.cnblogs.com/Mayfly-nymph/p/11869959.html#easyRE)，这真是道眼力题。。

- 进ida，首先看到start函数，啥也不是，翻string窗口，很显眼的`You found me`，跟进去

```c
__int64 sub_4009C6()
{
  __int64 result; // rax
  int i; // [rsp+Ch] [rbp-114h]
  __int64 v2; // [rsp+10h] [rbp-110h]
  __int64 v3; // [rsp+18h] [rbp-108h]
  __int64 v4; // [rsp+20h] [rbp-100h]
  __int64 v5; // [rsp+28h] [rbp-F8h]
  __int64 v6; // [rsp+30h] [rbp-F0h]
  __int64 v7; // [rsp+38h] [rbp-E8h]
  __int64 v8; // [rsp+40h] [rbp-E0h]
  __int64 v9; // [rsp+48h] [rbp-D8h]
  __int64 v10; // [rsp+50h] [rbp-D0h]
  __int64 v11; // [rsp+58h] [rbp-C8h]
  char v12[36]; // [rsp+60h] [rbp-C0h] BYREF
  char input1[32]; // [rsp+90h] [rbp-90h] BYREF
  int v14; // [rsp+B0h] [rbp-70h]
  char v15; // [rsp+B4h] [rbp-6Ch]
  char input2[72]; // [rsp+C0h] [rbp-60h] BYREF
  unsigned __int64 v17; // [rsp+108h] [rbp-18h]

  v17 = __readfsqword(0x28u);
  qmemcpy(v12, "Iodl>Qnb(ocy", 12);
  v12[12] = 127;
  qmemcpy(&v12[13], "y.i", 3);
  v12[16] = 127;
  qmemcpy(&v12[17], "d`3w}wek9{iy=~yL@EC", 19);
  memset(input1, 0, sizeof(input1));
  v14 = 0;
  v15 = 0;
  Read(0, input1, 0x25uLL);
  v15 = 0;
  if ( _strlen_sse2(input1) == 36 )
  {
    for ( i = 0; i < (unsigned __int64)_strlen_sse2(input1); ++i )
    {
      if ( (unsigned __int8)(input1[i] ^ i) != v12[i] )
      {
        result = 4294967294LL;
        goto LABEL_13;
      }
    }
    puts("continue!");
    memset(input2, 0, 0x40uLL);
    input2[64] = 0;
    Read(0, input2, 0x40uLL);
    input2[39] = 0;
    if ( _strlen_sse2(input2) == 39 )
    {
      v2 = Base64enc(input2);
      v3 = Base64enc(v2);
      v4 = Base64enc(v3);
      v5 = Base64enc(v4);
      v6 = Base64enc(v5);
      v7 = Base64enc(v6);
      v8 = Base64enc(v7);
      v9 = Base64enc(v8);
      v10 = Base64enc(v9);
      v11 = Base64enc(v10);
      if ( !(unsigned int)Strcmp(v11, off_6CC090) )
      {
        puts("You found me!!!");
        puts("bye bye~");
      }
      result = 0LL;
    }
    else
    {
      result = 4294967293LL;
    }
  }
  else
  {
    result = 0xFFFFFFFFLL;
  }
LABEL_13:
  if ( __readfsqword(0x28u) != v17 )
    sub_444020();
  return result;
}
```

- 两次输入，两次加密比较，都很常规

- 第一个异或解密

```python
enc1 = "Iodl>Qnb(ocy" + chr(127) + "y.i" + chr(127) + "d`3w}wek9{iy=~yL@EC"
print(len(enc1))
for i in range(36):
    print(chr(ord(enc1[i]) ^ i),end="")
#output： Info:The first four chars are `flag`
```

- 第二个可以看出来是base64加密了10遍，解密得到`https://bbs.pediy.com/thread-254172.htm`，然后寄！

- 翻各种奇奇怪怪的系统函数实现，也没看出来个所以然，看了看wp,其实上面文章中也有提示，但我也没认真看（（

- 在第二次加密后比较的字符串位置后面，还存着一个`规律的字符串`

![1.png](/upload/2022/02/1-894c9a9e28b846cf916e493cd21bbd98.png)

- 查交叉引用定位函数`sub_400D35`

```c
unsigned __int64 sub_400D35()
{
  unsigned __int64 result; // rax
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  int i; // [rsp+10h] [rbp-20h]
  int j; // [rsp+14h] [rbp-1Ch]
  unsigned int key; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = sub_43FD20(0LL) - qword_6CEE38;
  for ( i = 0; i <= 1233; ++i )
  {
    sub_40F790(v1);
    sub_40FE60();
    sub_40FE60();
    v1 = sub_40FE60() ^ 0x98765432;
  }
  key = v1;
  if ( ((unsigned __int8)v1 ^ a5VENbThlNr2e[0]) == 'f' && (HIBYTE(key) ^ a5VENbThlNr2e[3]) == 'g' )
  {
    for ( j = 0; j <= 24; ++j )
      putchar((unsigned __int8)(a5VENbThlNr2e[j] ^ *((_BYTE *)&key + j % 4)));
  }
  result = __readfsqword(0x28u) ^ v5;
  if ( result )
    sub_444020();
  return result;
}
```

- 第一次异或得到前四位为`flag`，第二次异或输出`flag`

```python
en_flag = [0x40, 0x35, 0x20, 0x56, 0x5D, 0x18, 0x22, 0x45, 0x17, 0x2F, 0x24, 0x6E, 0x62, 0x3C, 0x27, 0x54, 0x48, 0x6C, 0x24, 0x6E, 0x72, 0x3C, 0x32, 0x45, 0x5B, 0x00]
chars = "flag"
key = [0]*4
for i in range(4):
    key[i] = en_flag[i] ^ ord(chars[i])
for i in range(26):
    print(chr(en_flag[i] ^ key[i%4]),end="")
#output：flag{Act1ve_Defen5e_Test}
```

## [FlareOn4]login

- 解压压缩包得到一个html文件，源码如下

```html
<!DOCTYPE Html />
<html>
    <head>
        <title>FLARE On 2017</title>
    </head>
    <body>
        <input type="text" name="flag" id="flag" value="Enter the flag" />
        <input type="button" id="prompt" value="Click to check the flag" />
        <script type="text/javascript">
            document.getElementById("prompt").onclick = function () {
                var flag = document.getElementById("flag").value;
                var rotFlag = flag.replace(/[a-zA-Z]/g, function(c){return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);});
                if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
                    alert("Correct flag!");
                } else {
                    alert("Incorrect flag, rot again");
                }
            }
        </script>
    </body>
</html>
```

- 计算`rotFlag`属于是极致的压行了，为的就是让人迷糊看不懂，翻译成py大概长这样

```python
flag = "plain_text"
for i in range(36):
    if(flag[i] <= "Z"):
        t = 90
    else: t = 122
    flag[i] = chr(ord(flag[i]) + 13)
    if(t < flag[i]):
        flag[i] -= 26
```

- flag所有位会先加上13，然后如果符合if条件会再减26

- 要想完全理清楚一位一位逆回去很麻烦，但总的来说逆回去要么加13要么减13

- 盲猜flag是有意义的字符串，所以我把可能的情况全列出来（一位两种可能），人工挑选正确答案

```python
en_flag = "PyvragFvqrYbtvafNerRnfl@syner-ba.pbz"
for i in en_flag:
    if(i.isalpha() == False):#只替换flag中的字母
        print(i)
        continue
    if(ord(i)+ 13 <= 126):#加这个判断是因为如果超出可见字符，无法输出则排列会很难看
        print(chr(ord(i)+13),end="     ")
    print(chr(ord(i)-13))
```

- 程序输出

```text
]     C
l
i
e
n     T
t     Z
S     9
i
~     d
e
f     L
o     U
g
i
n     T
s     Y
[     A
r     X
e
_     E
{     a
s     Y
y     _
@
f
l
{     a
r     X
e
-
o     U
n     T
.
}     c
o     U
m
```

- 其中如果某一行既有字母又有非字母，可以直接舍弃非字母，因为非字母开始就不会被替换

- 仔细看一会，得到`flag{ClientSideLoginsAreEasy@flare-on.com}`

## [GUET-CTF2019]re

- 拖入ida发现函数很少，感觉有壳，果然是upx，先脱壳然后再进ida

- 主要函数

```c
__int64 __fastcall sub_400E28(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 result; // rax
  __int64 v7; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  Printf((__int64)"input your flag:", a2, a3, a4, a5, a6, 0LL, 0LL, 0LL, 0LL);
  Scanf((__int64)"%s", &v7);
  if ( sub_4009AE((char *)&v7) )
    puts("Correct!");
  else
    puts("Wrong!");
  result = 0LL;
  if ( __readfsqword(0x28u) != v8 )
    sub_443550();
  return result;
}
```

- 主要加密在sub_4009AE

```c
_BOOL8 __fastcall sub_4009AE(char *a1)
{
  if ( 1629056 * *a1 != 166163712 )
    return 0LL;
  if ( 6771600 * a1[1] != 731332800 )
    return 0LL;
  if ( 3682944 * a1[2] != 357245568 )
    return 0LL;
  if ( 10431000 * a1[3] != 1074393000 )
    return 0LL;
  if ( 3977328 * a1[4] != 489211344 )
    return 0LL;
  if ( 5138336 * a1[5] != 518971936 )
    return 0LL;
  if ( 7532250 * a1[7] != 406741500 )
    return 0LL;
  if ( 5551632 * a1[8] != 294236496 )
    return 0LL;
  if ( 3409728 * a1[9] != 177305856 )
    return 0LL;
  if ( 13013670 * a1[10] != 650683500 )
    return 0LL;
  if ( 6088797 * a1[11] != 298351053 )
    return 0LL;
  if ( 7884663 * a1[12] != 386348487 )
    return 0LL;
  if ( 8944053 * a1[13] != 438258597 )
    return 0LL;
  if ( 5198490 * a1[14] != 249527520 )
    return 0LL;
  if ( 4544518 * a1[15] != 445362764 )
    return 0LL;
  if ( 3645600 * a1[17] != 174988800 )
    return 0LL;
  if ( 10115280 * a1[16] != 981182160 )
    return 0LL;
  if ( 9667504 * a1[18] != 493042704 )
    return 0LL;
  if ( 5364450 * a1[19] != 257493600 )
    return 0LL;
  if ( 13464540 * a1[20] != 767478780 )
    return 0LL;
  if ( 5488432 * a1[21] != 312840624 )
    return 0LL;
  if ( 14479500 * a1[22] != 1404511500 )
    return 0LL;
  if ( 6451830 * a1[23] != 316139670 )
    return 0LL;
  if ( 6252576 * a1[24] != 619005024 )
    return 0LL;
  if ( 7763364 * a1[25] != 372641472 )
    return 0LL;
  if ( 7327320 * a1[26] != 373693320 )
    return 0LL;
  if ( 8741520 * a1[27] != 498266640 )
    return 0LL;
  if ( 8871876 * a1[28] != 452465676 )
    return 0LL;
  if ( 4086720 * a1[29] != 208422720 )
    return 0LL;
  if ( 9374400 * a1[30] == 515592000 )
    return 5759124 * a1[31] == 719890500;
  return 0LL;
}
```

- 上z3搞它

```python
from z3 import *

s = z3.Solver()
a1 = [Int('a1[%d]' % i) for i in range(32)]

s.add(1629056 * a1[0] == 166163712)
s.add(6771600 * a1[1] == 731332800)
s.add(3682944 * a1[2] == 357245568)
s.add(10431000 * a1[3] == 1074393000)
s.add(3977328 * a1[4] == 489211344)
s.add(5138336 * a1[5] == 518971936)
s.add(7532250 * a1[7] == 406741500)
s.add(5551632 * a1[8] == 294236496)
s.add(3409728 * a1[9] == 177305856)
s.add(13013670 * a1[10] == 650683500)
s.add(6088797 * a1[11] == 298351053)
s.add(7884663 * a1[12] == 386348487)
s.add(8944053 * a1[13] == 438258597)
s.add(5198490 * a1[14] == 249527520)
s.add(4544518 * a1[15] == 445362764)
s.add(3645600 * a1[17] == 174988800)
s.add(10115280 * a1[16] == 981182160)
s.add(9667504 * a1[18] == 493042704)
s.add(5364450 * a1[19] == 257493600)
s.add(13464540 * a1[20] == 767478780)
s.add(5488432 * a1[21] == 312840624)
s.add(14479500 * a1[22] == 1404511500)
s.add(6451830 * a1[23] == 316139670)
s.add(6252576 * a1[24] == 619005024)
s.add(7763364 * a1[25] == 372641472)
s.add(7327320 * a1[26] == 373693320)
s.add(8741520 * a1[27] == 498266640)
s.add(8871876 * a1[28] == 452465676)
s.add(4086720 * a1[29] == 208422720)
s.add(9374400 * a1[30] == 515592000)
s.add(5759124 * a1[31] == 719890500)
s.check()
print(s.model())
```

- 打印flag

```python
a1 = [0] * 32
a1[31] = 125
a1[30] = 55
a1[29] = 51
a1[28] = 51
a1[27] = 57
a1[26] = 51
a1[25] = 48
a1[24] = 99
a1[23] = 49
a1[22] = 97
a1[21] = 57
a1[20] = 57
a1[19] = 48
a1[18] = 51
a1[16] = 97
a1[17] = 48
a1[15] = 98
a1[14] = 48
a1[13] = 49
a1[12] = 49
a1[11] = 49
a1[10] = 50
a1[9] = 52
a1[8] = 53
a1[7] = 54
a1[5] = 101
a1[4] = 123
a1[3] = 103
a1[2] = 97
a1[1] = 108
a1[0] = 102
for i in range(32):
    print(chr(a1[i]),end="")
```

- 这里有两个小问题
  
  - 伪代码中16、17两位顺序反了，但因为z3搞的时候是顺着命名未知数的，所以反上加反等于顺序正确，不用修改
  
  - 另一点就是第6位缺失，并未进行判断，实测无论第6位是什么，源程序都会输出`Correct！`，应该是多解，但无奈buu平台上只认第6位为1

- 故`flag{e165421110ba03099a1c039337}`
  
  ## 

## [SUCTF2019]SignIn

- 进ida看到main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[16]; // [rsp+0h] [rbp-4A0h] BYREF
  char v5[16]; // [rsp+10h] [rbp-490h] BYREF
  char v6[16]; // [rsp+20h] [rbp-480h] BYREF
  char code[16]; // [rsp+30h] [rbp-470h] BYREF
  char v8[112]; // [rsp+40h] [rbp-460h] BYREF
  char v9[1000]; // [rsp+B0h] [rbp-3F0h] BYREF
  unsigned __int64 v10; // [rsp+498h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[sign in]");
  printf("[input your flag]: ");
  __isoc99_scanf("%99s", v8);
  sub_96A(v8, v9);
  __gmpz_init_set_str(code, "ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str(v6, v9, 16LL);
  __gmpz_init_set_str(v4, "103461035900816914121390101299049044413950405173712170434161686539878160984549", 10LL);
  __gmpz_init_set_str(v5, "65537", 10LL);
  __gmpz_powm(v6, v6, v5, v4);
  if ( (unsigned int)__gmpz_cmp(v6, code) )
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
  return 0LL;
}
```

- 标准的用gmp库实现的RSA算法

- 参考[gmpy2常见函数使用](https://blog.csdn.net/weixin_43790779/article/details/108473984) [RSA算法原理](https://blog.csdn.net/dbs1215/article/details/48953589)

- 利用gmpy2库解出flag

```python
import gmpy2
from Crypto.Util.number import *

n = 103461035900816914121390101299049044413950405173712170434161686539878160984549
p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419
code = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35
e = 65537
l = (p-1)*(q-1)
d = gmpy2.invert(e,l)
flag = gmpy2.powmod(code,d,n)
print(long_to_bytes(flag))
#output：b'suctf{Pwn_@_hundred_years}'
```

## [WUSTCTF2020]level1

- main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+4h] [rbp-2Ch]
  FILE *stream; // [rsp+8h] [rbp-28h]
  char ptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  stream = fopen("flag", "r");
  fread(ptr, 1uLL, 0x14uLL, stream);
  fclose(stream);
  for ( i = 1; i <= 19; ++i )
  {
    if ( (i & 1) != 0 )
      printf("%ld\n", (unsigned int)(ptr[i] << i));
    else
      printf("%ld\n", (unsigned int)(i * ptr[i]));
  }
  return 0;
}
```

- 有强转直接逆不太保险，正着直接爆出来

```c
#include<stdio.h>

int main(){
    unsigned int en_flag[] = {0,198,232,816,200,1536,300,6144,984,51200,570,92160,1200,565248,756,1474560,800,6291456,1782,65536000};
    char flag[19] = {0};

    for(int i = 1;i <= 19; i++){
        for(int j = 32; j <= 126; j++){
            unsigned int t;
            if(i & 1 != 0) t = (unsigned int)(j << i);
            else t = (unsigned int)(j * i);
            if(t == en_flag[i]) flag[i] = j;
        }
        printf("%c",flag[i]);
    }
}
//output：ctf2020{d9-dE6-20c}
```

- （这两天题咋越做越简单了，，
  
  ## [MRCTF2020]Transform

- 进ida就能看到main函数，简单改一下变量名

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Str[104]; // [rsp+20h] [rbp-70h] BYREF
  int j; // [rsp+88h] [rbp-8h]
  int i; // [rsp+8Ch] [rbp-4h]

  sub_402230(argc, argv, envp);
  Printf("Give me your code:\n");
  Scanf("%s", Str);
  if ( strlen(Str) != 33 )
  {
    Printf("Wrong!\n");
    system("pause");
    exit(0);
  }
  for ( i = 0; i <= 32; ++i )
  {
    en_flag[i] = Str[index[i]];
    en_flag[i] ^= LOBYTE(index[i]);
  }
  for ( j = 0; j <= 32; ++j )
  {
    if ( byte_40F0E0[j] != en_flag[j] )
    {
      Printf("Wrong!\n");
      system("pause");
      exit(0);
    }
  }
  Printf("Right!Good Job!\n");
  Printf("Here is your flag: %s\n", Str);
  system("pause");
  return 0;
}
```

- 直接逆拿flag

```python
index = [
 0x09, 0x0A, 0x0F, 0x17, 0x07, 0x18, 0x0C, 0x06,
 0x01, 0x10, 0x03, 0x11, 0x20, 0x1D, 0x0B, 0x1E, 
 0x1B, 0x16, 0x04, 0x0D, 0x13, 0x14, 0x15, 0x02, 
 0x19, 0x05, 0x1F, 0x08, 0x12, 0x1A, 0x1C, 0x0E,0]
en_flag = [
 0x67, 0x79, 0x7B, 0x7F, 0x75, 0x2B, 0x3C, 0x52, 
 0x53, 0x79, 0x57, 0x5E, 0x5D, 0x42, 0x7B, 0x2D, 
 0x2A, 0x66, 0x42, 0x7E, 0x4C, 0x57, 0x79, 0x41, 
 0x6B, 0x7E, 0x65, 0x3C, 0x5C, 0x45, 0x6F, 0x62, 0x4D]

flag = [0] * 33

for i in range(0,33):
    en_flag[i] ^= index[i]
    flag[index[i]] = en_flag[i]

for i in flag:
    print(chr(i), end = "")
#output：MRCTF{Tr4nsp0sltiON_Clph3r_1s_3z}
```

## [ACTF新生赛2020]usualCrypt

- 进ida看main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // esi
  int result; // eax
  int v5[3]; // [esp+8h] [ebp-74h] BYREF
  __int16 v6; // [esp+14h] [ebp-68h]
  char v7; // [esp+16h] [ebp-66h]
  char v8[100]; // [esp+18h] [ebp-64h] BYREF

  printf(asc_40E140);
  scanf("%s", v8);
  v5[0] = 0;
  v5[1] = 0;
  v5[2] = 0;
  v6 = 0;
  v7 = 0;
  encrypt((int)v8, strlen(v8), (int)v5);
  v3 = 0;
  while ( *((_BYTE *)v5 + v3) == enc[v3] )
  {
    if ( ++v3 > strlen((const char *)v5) )
      goto LABEL_6;
  }
  printf("error!\n");
LABEL_6:
  if ( v3 - 1 == strlen(enc) )
    result = printf("Are you happy?yes!\n");
  else
    result = printf("Are you happy?No!\n");
  return result;
}
```

- encrypt函数

```c
void __cdecl encrypt(int a1, int a2, int a3)
{
  int v3; // edi
  int v4; // esi
  int v5; // edx
  int v6; // eax
  int v7; // ecx
  int v8; // esi
  int v9; // esi
  int v10; // esi
  int v11; // esi
  _BYTE *v12; // ecx
  int v13; // esi
  int a2a; // [esp+18h] [ebp+8h]

  v3 = 0;
  v4 = 0;
  changeTable();                                // base64换表
  v5 = a2 % 3;
  v6 = a1;
  v7 = a2 - a2 % 3;
  a2a = a2 % 3;
  if ( v7 > 0 )
  {
    do
    {
      LOBYTE(v5) = *(_BYTE *)(a1 + v3);
      v3 += 3;
      v8 = v4 + 1;
      *(_BYTE *)(v8 + a3 - 1) = aAbcdefghijklmn[(v5 >> 2) & 0x3F];
      *(_BYTE *)(++v8 + a3 - 1) = aAbcdefghijklmn[16 * (*(_BYTE *)(a1 + v3 - 3) & 3)
                                                + (((int)*(unsigned __int8 *)(a1 + v3 - 2) >> 4) & 0xF)];
      *(_BYTE *)(++v8 + a3 - 1) = aAbcdefghijklmn[4 * (*(_BYTE *)(a1 + v3 - 2) & 0xF)
                                                + (((int)*(unsigned __int8 *)(a1 + v3 - 1) >> 6) & 3)];
      v5 = *(_BYTE *)(a1 + v3 - 1) & 0x3F;
      v4 = v8 + 1;
      *(_BYTE *)(v4 + a3 - 1) = aAbcdefghijklmn[v5];
    }
    while ( v3 < v7 );
    v5 = a2a;
  }
  if ( v5 == 1 )
  {
    LOBYTE(v7) = *(_BYTE *)(v3 + a1);
    v9 = v4 + 1;
    *(_BYTE *)(v9 + a3 - 1) = aAbcdefghijklmn[(v7 >> 2) & 0x3F];
    v10 = v9 + 1;
    *(_BYTE *)(v10 + a3 - 1) = aAbcdefghijklmn[16 * (*(_BYTE *)(v3 + a1) & 3)];
    *(_BYTE *)(v10 + a3) = 61;
LABEL_8:
    v13 = v10 + 1;
    *(_BYTE *)(v13 + a3) = 61;
    v4 = v13 + 1;
    goto LABEL_9;
  }
  if ( v5 == 2 )
  {
    v11 = v4 + 1;
    *(_BYTE *)(v11 + a3 - 1) = aAbcdefghijklmn[((int)*(unsigned __int8 *)(v3 + a1) >> 2) & 0x3F];
    v12 = (_BYTE *)(v3 + a1 + 1);
    LOBYTE(v6) = *v12;
    v10 = v11 + 1;
    *(_BYTE *)(v10 + a3 - 1) = aAbcdefghijklmn[16 * (*(_BYTE *)(v3 + a1) & 3) + ((v6 >> 4) & 0xF)];
    *(_BYTE *)(v10 + a3) = aAbcdefghijklmn[4 * (*v12 & 0xF)];
    goto LABEL_8;
  }
LABEL_9:
  *(_BYTE *)(v4 + a3) = 0;
  switch((const char *)a3);                     // 大小写转换
}
```

- 出题人在寒顺的开头和结尾耍了一点小心思

- 上面先简单的换了个base64的表，下面把base64编码后的字符串中的字母进行大小写转换

- 最终得到的字符串与已知字符串比较

- 写脚本拿flag

```python
import base64
enc = "zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9"
ch = ""
for i in enc:
    if(ord(i) < 97 or ord(i) > 122):
        if(ord(i) < 65 or ord(i) > 90):
            ch += i
            continue
        ch += chr(ord(i) + 32)
    else: ch += chr(ord(i) - 32)

old_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
new_table = "ABCDEFQRSTUVWXYPGHIJKLMNOZabcdefghijklmnopqrstuvwxyz0123456789+/"
table = str.maketrans(old_table, new_table)
print(base64.b64decode(ch.translate(table)))
#output：b'flag{bAse64_h2s_a_Surprise}'
```

## Youngter-drive

- 参考[g0ul4sh的wp](https://g0ul4sh.top/2018/07/22/anheng-july-re-youngter-drive/)，大佬写得很详细，学到很多

- 总的来说，这是一道很有意思的题

- 先要脱upx壳，然后拖进ida，main函数

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  void *v3; // ecx
  HANDLE v5; // [esp+D0h] [ebp-14h]
  HANDLE hObject; // [esp+DCh] [ebp-8h]

  ini(v3);
  ::hObject = CreateMutexW(0, 0, 0);
  j_strcpy(Destination, (const char *)Source);
  hObject = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)StartAddress, 0, 0, 0);
  v5 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)sub_41119F, 0, 0, 0);
  CloseHandle(hObject);
  CloseHandle(v5);
  while ( dword_418008 != -1 )
    ;
  sub_411190();
  CloseHandle(::hObject);
  return 0;
}
```

> `CreateThread` API 会创建新线程，这道题涉及到多线程。`CreateMutex` 创建一个[互斥体](https://zh.wikipedia.org/wiki/%E4%BA%92%E6%96%A5%E9%94%81)，用于防止多线程中出现资源争用，即多个线程同时读写同一个资源的情况，所创建的互斥体的句柄会存到全局变量 `hObject` 中（注意前面的两个冒号表示是全局变量，而不是这个函数里同名的局部变量）。这里创建了两个线程，入口点分别位于函数 `StartAddress` 和 `sub_41119F`

- `StartAddress`线程内部函数

```c

void __stdcall StartAddress_0(int a1)
{
  while ( 1 )
  {
    WaitForSingleObject(hObject, 0xFFFFFFFF);
    if ( dword_418008 > -1 )
    {
      sub_41112C((int)Source, (char *)dword_418008);
      --dword_418008;
      Sleep(0x64u);
    }
    ReleaseMutex(hObject);
  }
}
```

```c
//sub_41112C内部嵌套sub_411940
void __cdecl sub_411940(int a1, char *a2)
{
  char v2; // [esp+D3h] [ebp-5h]

  v2 = a2[a1];
  if ( (v2 < 'a' || v2 > 'z') && (v2 < 'A' || v2 > 'Z') )
    exit(0);
  if ( v2 < 'a' || v2 > 'z' )
    a2[a1] = off_418000[0][a2[a1] - 38];
  else
    a2[a1] = off_418000[0][a2[a1] - 96];
}
```

- 这里发现个小问题，通过函数实现判断sub__41112C函数和内部sub_411940函数参数顺序颠倒，猜测是stdcall和cdecl传参顺序不同引起的，但ida识别错误

- `sub_41119F`线程内部函数

```c
void __stdcall sub_411B10(int a1)
{
  while ( 1 )
  {
    WaitForSingleObject(hObject, 0xFFFFFFFF);
    if ( dword_418008 > -1 )
    {
      Sleep(0x64u);
      --dword_418008;
    }
    ReleaseMutex(hObject);
  }
}
```

- 自己做的时候不懂多线程，以为这个函数没啥用，导致卡死

> 查 MSDN 知，可以用 `WaitForSingleObject` 等待互斥体的使用权（ownership）空闲出来，并获取使用权，然后再访问和其他线程共享的资源，访问完后，用 `ReleaseMutex` 释放使用权，给其他线程使用的机会[4](https://g0ul4sh.top/2018/07/22/anheng-july-re-youngter-drive/#fn4)。通过比较两线程的函数，很容易知道所共享的资源就是全局变量 `dword_418008`，它的初值是 29。而这两个线程一前一后创建，理论上是 `StartAddress` 先获得使用权，后来的 `sub_41119F` 进入等待状态，前者执行一次循环后释放使用权，与此同时后者等待结束、获得使用权，进入循环，循环完后释放使用权，前者又获得使用权，如此循环往复。也就是说，两个线程的操作是交替进行的。

- 故实现的功能是奇数位加密，偶数位不变

- 还是喜欢直接爆

```python
table = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm\0"
cmp_code = "TOiZiZtOrYaToUwPnToBsOaOapsyS\0"
inp = ""

for i in range(0,29):
    if(i % 2 == 0):
        inp += cmp_code[i]
    else:
        for j in range(0,127):
            if ( (j < ord('a') or j > ord('z')) and (j < ord('A') or j > ord('Z')) ):
                continue
            if ( j < 97 or j > 122 ):
                if(cmp_code[i] == table[j - 38]):
                    inp += chr(j)
            else:
                if(cmp_code[i] == table[j - 96]):
                    inp += chr(j)
print(inp)
#output：ThisisthreadofwindowshahaIsES
```

- 爆破中间又发现了个算法的小问题，按这样加密table中的第一位永远也用不到，且必须最后加个\0才能防止数组下标越界，可能是出题人的疏忽，还是故意？

- 最后还有个小坑，输入应该为30位，但程序验证的即我们所能解出的只有29位，应为多解，但出题人以及buu平台上默认最后一位是E才能correct

- 总结一下，这道题集合了upx脱壳，反调试（但可以像我一样只静态分析），多线程这么多知识点，可以说十分优秀了，也让我学到了很多
  
  ## [WUSTCTF2020]level2

- 没啥说的，纯新手题，upx脱个壳，ida打开汇编main函数就能看到flag{Just_upx_-d}
  
  ## 相册

- 安卓逆向，就对着jeb使劲翻吧

- 有一个C2类比较有用

```java
package cn.baidujiayuan.ver5304;

import android.content.Context;
import com.net.cn.NativeMethod;
import it.sauronsoftware.base64.Base64;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;

public class C2 {
    public static final String CANCELNUMBER = "%23%2321%23";
    public static final String MAILFROME = null;
    public static final String MAILHOST = "smtp.163.com";
    public static final String MAILPASS = null;
    public static final String MAILSERVER = null;
    public static final String MAILUSER = null;
    public static final String MOVENUMBER = "**21*121%23";
    public static final String PORT = "25";
    public static final String date = "2115-11-1";
    public static final String phoneNumber;

    static {
        System.loadLibrary("core");
        C2.MAILSERVER = Base64.decode(NativeMethod.m());
        C2.MAILUSER = Base64.decode(NativeMethod.m());
        C2.MAILPASS = Base64.decode(NativeMethod.pwd());
        C2.MAILFROME = Base64.decode(NativeMethod.m());
        C2.phoneNumber = Base64.decode(NativeMethod.p());
    }

    public C2() {
        super();
    }

    public static boolean isFilter(Context arg6) {
        boolean v2 = C2.strToDateLong("2115-11-1").getTime() - new Date().getTime() < 0 ? true : false;
        return v2;
    }

    public static boolean isServerFilter(Context arg5) {
        boolean v2 = false;
        if(arg5.getSharedPreferences("X", 0).getString("m", "1").equals("1")) {
            v2 = true;
        }

        return v2;
    }

    public static Date strToDateLong(String arg4) {
        return new SimpleDateFormat("yyyy-MM-dd").parse(arg4, new ParsePosition(0));
    }
}
```

- 可以看到像`MAILUSER``MAILPASS`这样的变量很像是我们所要的邮箱

- 但还是对java/jeb不熟悉，单知道JNI却不知道NativeMethod，还以为是什么内置函数，找半天也找不到，后面查到[有关java中的native](https://www.baeldung.com/java-native)才懂原来和JNI基本是一个东西

- 于是解压apk，在lib文件夹中找到so文件，拖进ida，找export，看到了`Java_com_net_cn_NativeMethod_m`，跟进去就能看到base64编码的字符串`MTgyMTg0NjUxMjVAMTYzLmNvbQ==`

- base64decode得邮箱`18218465125@163.com`
  
  ## [MRCTF2020]Xor

- 异或拿flag
  
  ## [HDCTF2019]Maze

- upx脱壳，进ida

- 有个花指令，稍微修一下，就能F5了，main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+10h] [ebp-14h]
  char v5[16]; // [esp+14h] [ebp-10h] BYREF

  printf("Go through the maze to get the flag!\n");
  scanf("%14s", v5);
  for ( i = 0; i <= 13; ++i )
  {
    switch ( v5[i] )
    {
      case 'a':
        --dword_408078;
        break;
      case 'd':
        ++dword_408078;
        break;
      case 's':
        --dword_40807C;
        break;
      case 'w':
        ++dword_40807C;
        break;
      default:
        continue;
    }
  }
  if ( dword_408078 == 5 && dword_40807C == -4 )
  {
    printf("Congratulations!\n");
    printf("Here is the flag:flag{%s}\n", v5);
  }
  else
  {
    printf("Try again...\n");
  }
  return 0;
}
```

- string窗口翻翻就能找到地图，总共70个字符，试了试应该是10*7

```python
'*', '*', '*', '*', '*', '*', '*', '+', '*', '*'
'*', '*', '*', '*', '*', '*', '*', ' ', '*', '*'
'*', '*', '*', '*', ' ', ' ', ' ', ' ', '*', '*'
'*', '*', ' ', ' ', ' ', '*', '*', '*', '*', '*'
'*', '*', ' ', '*', '*', 'F', '*', '*', '*', '*'
'*', '*', ' ', ' ', ' ', ' ', '*', '*', '*', '*'
'*', '*', '*', '*', '*', '*', '*', '*', '*', '*'
```

- 手动走一下ssaaasaassdddw，即flag{ssaaasaassdddw}
  
  ## [GWCTF 2019]xxor

- main函数

```c
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+8h] [rbp-68h]
  int j; // [rsp+Ch] [rbp-64h]
  int v6[6]; // [rsp+10h] [rbp-60h] OVERLAPPED BYREF
  __int128 v7; // [rsp+28h] [rbp-48h]
  int v8[6]; // [rsp+40h] [rbp-30h] OVERLAPPED BYREF
  __int128 v9; // [rsp+58h] [rbp-18h]
  unsigned __int64 v10; // [rsp+68h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("Let us play a game?");
  puts("you have six chances to input");
  puts("Come on!");
  *(_OWORD *)v6 = 0uLL;
  *(_QWORD *)&v6[4] = 0LL;
  v7 = 0uLL;
  for ( i = 0; i <= 5; ++i )
  {
    printf("%s", "input: ");
    __isoc99_scanf("%d", &v6[i]);
  }
  *(_OWORD *)v8 = 0uLL;
  *(_QWORD *)&v8[4] = 0LL;
  v9 = 0uLL;
  for ( j = 0; j <= 4; j += 2 )
  {
    lowInt = v6[j];
    highInt = v6[j + 1];
    teaCrypt(&lowInt, &dword_601060);
    v8[j] = lowInt;
    v8[j + 1] = highInt;
  }
  if ( (unsigned int)sub_400770(v8) != 1 )
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

- 输入六串数字，先进行tea加密，然后进sub_400770要解一个小方程组

```c
__int64 __fastcall teaCrypt(unsigned int *a1, _DWORD *a2)
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
    v5 += 1166789954;
    v3 += (v4 + v5 + 11) ^ ((v4 << 6) + *a2) ^ ((v4 >> 9) + a2[1]) ^ 0x20;
    v4 += (v3 + v5 + 20) ^ ((v3 << 6) + a2[2]) ^ ((v3 >> 9) + a2[3]) ^ 0x10;
  }
  *a1 = v3;
  result = v4;
  a1[1] = v4;
  return result;
}
```

```c
__int64 __fastcall sub_400770(int *a1)
{
  __int64 result; // rax

  if ( a1[2] - a1[3] == 2225223423LL
    && a1[3] + a1[4] == 4201428739LL
    && a1[2] - a1[4] == 1121399208LL
    && *a1 == -548868226
    && a1[5] == -2064448480
    && a1[1] == 550153460 )
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

- 逆过来先z3解方程

```python
from z3 import *
s = z3.Solver()
a2 = Int("a1[2]")
a3 = Int("a1[3]")
a4 = Int("a1[4]")   
s.add(a2 - a3 == 0x84A236FF)
s.add(a3 + a4 == 0xFA6CB703)
s.add(a2 - a4 == 0x42D731A8) 
s.check()
print(s.model())
#    && *a1 == -548868226
#    && a1[5] == -2064448480
#    && a1[1] == 550153460
# output：[a1[2] = 3774025685, a1[3] = 1548802262, a1[4] = 2652626477]
```

- 然后tea解密

```c
#include<stdio.h>
int main(){
    unsigned int a1[6] = {0xDF48EF7E, 0x20CAACF4, 3774025685, 1548802262, 2652626477, 0x84F30420};
    int key[] = {2, 2, 3, 4};
    for(int i = 0 ;i <= 2; i++){
        unsigned int lowbytes = a1[2 * i];
        unsigned int highbytes = a1[2 * i + 1];
        for(int j = 0x3f; j >= 0; j--){
            int delta = 1166789954 * (j + 1);
            highbytes -= (lowbytes + delta + 20) ^ ((lowbytes << 6) + key[2]) ^ ((lowbytes >> 9) + key[3]) ^ 0x10;
            lowbytes -= (highbytes + delta + 11) ^ ((highbytes << 6) + key[0]) ^ ((highbytes >> 9) + key[1]) ^ 0x20;
        }
        a1[2 * i] = lowbytes;
        a1[2 * i + 1] = highbytes;
    }
    for(int i = 0; i <= 5; i++){
        printf("%x", a1[i]);
    }
    return 0;
}
//output：666c61677b72655f69735f6772656174217d⏎
```

- long_to_bytes一下拿flag{re_is_great!}
  
  ## [MRCTF2020]hello_world_go

- main函数

```c
void __cdecl main_main()
{
  int v0; // edi
  __int64 v1; // rsi
  __int64 v2; // r8
  __int64 v3; // r9
  __int64 v4; // r8
  __int64 v5; // r9
  int v6; // edx
  __int64 v7; // r8
  __int64 v8; // r9
  __int64 v9; // rcx
  __int64 v10; // rax
  int v11; // edx
  __int64 v12; // rax
  __int64 *v13; // [rsp+8h] [rbp-A8h]
  char v14; // [rsp+18h] [rbp-98h]
  __int64 v15; // [rsp+20h] [rbp-90h]
  __int64 v16; // [rsp+28h] [rbp-88h]
  __int64 v17; // [rsp+58h] [rbp-58h]
  __int64 *v18; // [rsp+60h] [rbp-50h]
  __int128 v19; // [rsp+68h] [rbp-48h] BYREF
  void *v20; // [rsp+78h] [rbp-38h] BYREF
  void **v21; // [rsp+80h] [rbp-30h] BYREF
  __int128 v22; // [rsp+88h] [rbp-28h] BYREF
  __int128 v23; // [rsp+98h] [rbp-18h] BYREF

  if ( (unsigned __int64)&v21 <= *(_QWORD *)(__readfsqword(0xFFFFFFF8) + 16) )
    runtime_morestack_noctxt();
  runtime_newobject(v0, v1);
  v18 = v13;
  *(_QWORD *)&v23 = &unk_4AC9C0;
  *((_QWORD *)&v23 + 1) = &off_4EA530;
  fmt_Fprint(
    v0,
    v1,
    (unsigned int)&v23,
    (unsigned int)&unk_4AC9C0,
    v2,
    v3,
    (__int64)&go_itab__os_File_io_Writer,
    os_Stdout,
    (__int64)&v23);
  *(_QWORD *)&v22 = &unk_4A96A0;
  *((_QWORD *)&v22 + 1) = v18;
  fmt_Fscanf(
    v0,
    v1,
    (unsigned int)&go_itab__os_File_io_Reader,
    (unsigned int)&v22,
    v4,
    v5,
    (__int64)&go_itab__os_File_io_Reader,
    os_Stdin,
    (__int64)&unk_4D07C9,
    2LL,
    (__int64)&v22,
    1LL);
  v9 = v18[1];
  v10 = *v18;
  if ( v9 != 24 )
    goto LABEL_3;
  v17 = *v18;
  runtime_memequal(v0, v1, v6, (unsigned int)aFlagHelloWorld, v7, v8, (__int64)aFlagHelloWorld, v10);
  if ( !v14 )
  {
    LOBYTE(v10) = v17;
    LODWORD(v9) = 24;
LABEL_3:
    runtime_cmpstring(v0, v1, (unsigned int)aFlagHelloWorld, v9, v7, v8, (__int64)aFlagHelloWorld, 24LL, v10);
    if ( v15 >= 0 )
      v12 = 1LL;
    else
      v12 = -1LL;
    goto LABEL_5;
  }
  v12 = 0LL;
LABEL_5:
  if ( v12 )
  {
    *(_QWORD *)&v19 = &unk_4AC9C0;
    *((_QWORD *)&v19 + 1) = &off_4EA550;
    fmt_Fprintln(
      v0,
      v1,
      v11,
      (unsigned int)&go_itab__os_File_io_Writer,
      v7,
      v8,
      (__int64)&go_itab__os_File_io_Writer,
      os_Stdout,
      (__int64)&v19,
      1LL,
      1LL,
      v16);
  }
  else
  {
    v20 = &unk_4AC9C0;
    v21 = &off_4EA540;
    fmt_Fprintln(
      v0,
      v1,
      v11,
      (unsigned int)&go_itab__os_File_io_Writer,
      v7,
      v8,
      (__int64)&go_itab__os_File_io_Writer,
      os_Stdout,
      (__int64)&v20,
      1LL,
      1LL,
      v16);
  }
}
```

- 翻aFlagHelloWorld就能看到flag{hello_world_gogogo}

- 这道题最有用的是让我装了idaGolangHelper
  
  ## [WUSTCTF2020]level3

- main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  char v5; // [rsp+Fh] [rbp-41h]
  char v6[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  printf("Try my base64 program?.....\n>");
  __isoc99_scanf("%20s", v6);
  v5 = time(0LL);
  srand(v5);
  if ( (rand() & 1) != 0 )
  {
    v3 = base64_encode(v6);
    puts(v3);
    puts("Is there something wrong?");
  }
  else
  {
    puts("Sorry I think it's not prepared yet....");
    puts("And I get a strange string from my program which is different from the standard base64:");
    puts("d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD==");
    puts("What's wrong??");
  }
  return 0;
}
```

- 可以看出最终flag是这段字符串`d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD==`base64解密得到的

- 但标准base64解密出来是乱码，说明对base64做了手脚、

- 其实是在start函数中藏了一个换表的操作

```c
__int64 O_OLookAtYou()
{
  __int64 result; // rax
  char v1; // [rsp+1h] [rbp-5h]
  int i; // [rsp+2h] [rbp-4h]

  for ( i = 0; i <= 9; ++i )
  {
    v1 = base64_table[i];
    base64_table[i] = base64_table[19 - i];
    result = 19 - i;
    base64_table[result] = v1;
  }
  return result;
}
```

- 可以计算拿到新表，但更好的方法是直接动调就能拿到新表

- 写脚本拿flag

```python
import base64
new_table = "TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
enc = "d2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD=="
table = str.maketrans(standard_table, new_table)
print(base64.b64decode(enc.translate(table)))
#output：b'wctf2020{Base64_is_the_start_of_reverse}'
```

## [FlareOn4]IgniteMe

- main函数

```c
void __thiscall __noreturn start(char *Format)
{
  DWORD NumberOfBytesWritten; // [esp+0h] [ebp-4h] BYREF

  NumberOfBytesWritten = 0;
  hFile = GetStdHandle(0xFFFFFFF6);
  dword_403074 = GetStdHandle(0xFFFFFFF5);
  WriteFile(dword_403074, aG1v3M3T3hFl4g, 0x13u, &NumberOfBytesWritten, 0);
  Scanf((const char *const)NumberOfBytesWritten);
  if ( check() )
    WriteFile(dword_403074, aG00dJ0b, 0xAu, &NumberOfBytesWritten, 0);
  else
    WriteFile(dword_403074, aN0tT00H0tRWe7r, 0x24u, &NumberOfBytesWritten, 0);
  ExitProcess(0);
}
```

- 主要内容在check函数

```c
int sub_401050()
{
  int v1; // [esp+0h] [ebp-Ch]
  int i; // [esp+4h] [ebp-8h]
  unsigned int j; // [esp+4h] [ebp-8h]
  char v4; // [esp+Bh] [ebp-1h]

  v1 = strlen((int)input);
  v4 = key();
  for ( i = v1 - 1; i >= 0; --i )
  {
    byte_403180[i] = v4 ^ input[i];
    v4 = input[i];
  }
  for ( j = 0; j < 0x27; ++j )
  {
    if ( byte_403180[j] != (unsigned __int8)enc[j] )
      return 0;
  }
  return 1;
}
```

- 异或拿flag

```python
enc = [0x0D, 0x26, 0x49, 0x45, 0x2A, 0x17, 0x78, 0x44, 0x2B, 0x6C, 0x5D, 0x5E, 0x45, 0x12, 0x2F, 0x17, 0x2B, 0x44, 0x6F, 0x6E, 0x56, 0x09, 0x5F, 0x45, 0x47, 0x73, 0x26, 0x0A, 0x0D, 0x13, 0x17, 0x48, 0x42, 0x01, 0x40, 0x4D, 0x0C, 0x02, 0x69, 0x00]
key = 4
flag = [0] * 40
for i in range(38, -1, -1):
    flag[i] = enc[i] ^ key
    key = flag[i]
for i in flag:
    print(chr(i), end = "")
#output:R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com
```

## [FlareOn6]Overlong

- 由题目结合数组猜测数据没有打印完全

- 把代码dump下来，循环次数加大，运行即可拿flag

```c
#include<stdio.h>
int cal(char *c, char *byte){
    int v3;
    char v4;
    if ( (int)(unsigned char)*byte >> 3 == 30 ){
        v4 = byte[3] & 0x3F | ((byte[2] & 0x3F) << 6);
        v3 = 4;
    }
    else if ( (int)(unsigned char)*byte >> 4 == 14 ){
        v4 = byte[2] & 0x3F | ((byte[1] & 0x3F) << 6);
        v3 = 3;
    }
    else if ( (int)(unsigned char)*byte >> 5 == 6 ){
        v4 = byte[1] & 0x3F | ((*byte & 0x1F) << 6);
        v3 = 2;
    }
    else{
        v4 = *byte;
        v3 = 1;
    }
    *c = v4;
    return v3;
}
int main(){
    unsigned char bytecode[176] = {
    0xE0, 0x81, 0x89, 0xC0, 0xA0, 0xC1, 0xAE, 0xE0, 0x81, 0xA5, 0xC1, 0xB6, 0xF0, 0x80, 0x81, 0xA5, 
    0xE0, 0x81, 0xB2, 0xF0, 0x80, 0x80, 0xA0, 0xE0, 0x81, 0xA2, 0x72, 0x6F, 0xC1, 0xAB, 0x65, 0xE0, 
    0x80, 0xA0, 0xE0, 0x81, 0xB4, 0xE0, 0x81, 0xA8, 0xC1, 0xA5, 0x20, 0xC1, 0xA5, 0xE0, 0x81, 0xAE, 
    0x63, 0xC1, 0xAF, 0xE0, 0x81, 0xA4, 0xF0, 0x80, 0x81, 0xA9, 0x6E, 0xC1, 0xA7, 0xC0, 0xBA, 0x20, 
    0x49, 0xF0, 0x80, 0x81, 0x9F, 0xC1, 0xA1, 0xC1, 0x9F, 0xC1, 0x8D, 0xE0, 0x81, 0x9F, 0xC1, 0xB4, 
    0xF0, 0x80, 0x81, 0x9F, 0xF0, 0x80, 0x81, 0xA8, 0xC1, 0x9F, 0xF0, 0x80, 0x81, 0xA5, 0xE0, 0x81, 
    0x9F, 0xC1, 0xA5, 0xE0, 0x81, 0x9F, 0xF0, 0x80, 0x81, 0xAE, 0xC1, 0x9F, 0xF0, 0x80, 0x81, 0x83, 
    0xC1, 0x9F, 0xE0, 0x81, 0xAF, 0xE0, 0x81, 0x9F, 0xC1, 0x84, 0x5F, 0xE0, 0x81, 0xA9, 0xF0, 0x80, 
    0x81, 0x9F, 0x6E, 0xE0, 0x81, 0x9F, 0xE0, 0x81, 0xA7, 0xE0, 0x81, 0x80, 0xF0, 0x80, 0x81, 0xA6, 
    0xF0, 0x80, 0x81, 0xAC, 0xE0, 0x81, 0xA1, 0xC1, 0xB2, 0xC1, 0xA5, 0xF0, 0x80, 0x80, 0xAD, 0xF0, 
    0x80, 0x81, 0xAF, 0x6E, 0xC0, 0xAE, 0xF0, 0x80, 0x81, 0xA3, 0x6F, 0xF0, 0x80, 0x81, 0xAD, 0x00
    };
    char *byte = bytecode;
    char c;
    char flag[100];
    for(int i = 0; i <= 100; i++){
        byte += cal(&c, byte);
        putchar(c);
    }
}
//output：I never broke the encoding: I_a_M_t_h_e_e_n_C_o_D_i_n_g@flare-on.com
```

## [FlareOn3]Challenge1

- main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int8 Buffer[128]; // [esp+0h] [ebp-94h] BYREF
  char *Str1; // [esp+80h] [ebp-14h]
  char *Str2; // [esp+84h] [ebp-10h]
  HANDLE v7; // [esp+88h] [ebp-Ch]
  HANDLE hFile; // [esp+8Ch] [ebp-8h]
  DWORD NumberOfBytesWritten; // [esp+90h] [ebp-4h] BYREF

  hFile = GetStdHandle(0xFFFFFFF5);
  v7 = GetStdHandle(0xFFFFFFF6);
  Str2 = "x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q";
  WriteFile(hFile, "Enter password:\r\n", 0x12u, &NumberOfBytesWritten, 0);
  ReadFile(v7, Buffer, 0x80u, &NumberOfBytesWritten, 0);
  Str1 = sub_401260(Buffer, NumberOfBytesWritten - 2);
  if ( !strcmp(Str1, Str2) )
    WriteFile(hFile, "Correct!\r\n", 0xBu, &NumberOfBytesWritten, 0);
  else
    WriteFile(hFile, "Wrong password\r\n", 0x11u, &NumberOfBytesWritten, 0);
  return 0;
}
```

- sub_401260函数

```c
char *__cdecl sub_401260(unsigned __int8 *input, unsigned int cnt)
{
  int v3; // [esp+Ch] [ebp-24h]
  int v4; // [esp+10h] [ebp-20h]
  int v5; // [esp+14h] [ebp-1Ch]
  int i; // [esp+1Ch] [ebp-14h]
  unsigned int v7; // [esp+20h] [ebp-10h]
  char *v8; // [esp+24h] [ebp-Ch]
  int v9; // [esp+28h] [ebp-8h]
  int v10; // [esp+28h] [ebp-8h]
  unsigned int v11; // [esp+2Ch] [ebp-4h]

  v8 = (char *)malloc(4 * ((cnt + 2) / 3) + 1);
  if ( !v8 )
    return 0;
  v11 = 0;
  v9 = 0;
  while ( v11 < cnt )
  {
    v5 = input[v11];
    if ( ++v11 >= cnt )
      v4 = 0;
    else
      v4 = input[v11++];
    if ( v11 >= cnt )
      v3 = 0;
    else
      v3 = input[v11++];
    v7 = v3 + (v5 << 16) + (v4 << 8);
    v8[v9] = aZyxabcdefghijk[(v7 >> 18) & 0x3F];
    v10 = v9 + 1;
    v8[v10] = aZyxabcdefghijk[(v7 >> 12) & 0x3F];
    v8[++v10] = aZyxabcdefghijk[(v7 >> 6) & 0x3F];
    v8[++v10] = aZyxabcdefghijk[v3 & 0x3F];
    v9 = v10 + 1;
  }
  for ( i = 0; i < *(_DWORD *)&aZyxabcdefghijk[4 * (cnt % 3) + 64]; ++i )
    v8[4 * ((cnt + 2) / 3) - i - 1] = 61;
  v8[4 * ((cnt + 2) / 3)] = 0;
  return v8;
}
```

- 看到下面的`aZyxabcdefghijk`就感觉有点base64换表那味，试了一下，还真是

- 脚本

```python
import base64
standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
new_table = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/"
table = str.maketrans(new_table, standard_table)
enc = "x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q"
print(base64.b64decode(enc.translate(table)))
#sh00ting_phish_in_a_barrel@flare-on.com
```

## [ACTF新生赛2020]Oruga

- 新颖的迷宫题

- 逻辑函数

```c
bool __fastcall sub_78A(char *input)
{
  int v2; // [rsp+Ch] [rbp-Ch]
  int v3; // [rsp+10h] [rbp-8h]
  int head; // [rsp+14h] [rbp-4h]

  v2 = 0;
  v3 = 5;
  head = 0;
  while ( byte_201020[v2] != '!' )
  {
    v2 -= head;
    if ( input[v3] != 'W' || head == -16 )
    {
      if ( input[v3] != 'E' || head == 1 )
      {
        if ( input[v3] != 'M' || head == 16 )
        {
          if ( input[v3] != 'J' || head == -1 )
            return 0;
          head = -1;
        }
        else
        {
          head = 16;
        }
      }
      else
      {
        head = 1;
      }
    }
    else
    {
      head = -16;
    }
    ++v3;
    while ( !byte_201020[v2] )
    {
      if ( head == -1 && (v2 & 0xF) == 0 )
        return 0;
      if ( head == 1 && v2 % 16 == 15 )
        return 0;
      if ( head == 16 && (unsigned int)(v2 - 240) <= 0xF )
        return 0;
      if ( head == -16 && (unsigned int)(v2 + 15) <= 0x1E )
        return 0;
      v2 += head;
    }
  }
  return input[v3] == '}';
}
```

- 只要当前字符为0,就朝一个方向一直走下去，越界就寄了

- 手动走一下

![Screenshot_20220322_232549.png](/upload/2022/03/Screenshot_20220322_232549-da5833c3aec84b19861dfacea1d53823.png)

- flag：actf{MEWEMEWJMEWJM}
  
  ## [Zer0pts2020]easy strcmp

- 出题人在main函数之前修改了strcmp函数

- 动调找到修改后的代码

```c
__int64 __fastcall sub_559B072006EA(char *a1, __int64 a2)
{
  int i; // [rsp+18h] [rbp-8h]
  int v4; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; a1[i]; ++i )
    ;
  v4 = (i >> 3) + 1;
  for ( j = 0; j < v4; ++j )
    *(_QWORD *)&a1[8 * j] -= qword_559B07401060[j];
  return off_559B07401090(a1, a2);
}
```

- 其实是把input减去qword_559B07401060与`zer0pts{********CENSORED********}`比较

- 刚开始想逐位解密，但发现中间8位有问题，应该是有进位的原因

- 还是得强转成qword运算，但实测这么算出来最后会多一位`*`，删掉即可

```c
#include<stdio.h>
int main(){
    unsigned long long key[] = {0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B};
    char en_flag[] = "********CENSORED********";
    char flag[] = "";
    for(int i = 0; i < 3; i++){
        *((long long *)flag + i) = *((long long *)en_flag + i) + key[i];
    }
    puts(flag);
    //l3ts_m4k3_4_DETOUR_t0d4y*
}
```

- flag{l3ts_m4k3_4_DETOUR_t0d4y}
  
  ## [ACTF新生赛2020]Universe_final_answer

- main函数

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[32]; // [rsp+0h] [rbp-A8h] BYREF
  char input[104]; // [rsp+20h] [rbp-88h] BYREF
  unsigned __int64 v6; // [rsp+88h] [rbp-20h]

  v6 = __readfsqword(0x28u);
  __printf_chk(1LL, "Please give me the key string:", a3);
  scanf("%s", input);
  if ( sub_860(input) )
  {
    sub_C50(input, v4);
    __printf_chk(1LL, "Judgement pass! flag is actf{%s_%s}\n", input);
  }
  else
  {
    puts("False key!");
  }
  return 0LL;
}
```

- 验证函数

```c
bool __fastcall sub_860(char *a1)
{
  int v1; // ecx
  int v2; // esi
  int v3; // edx
  int v4; // er9
  int v5; // er11
  int v6; // ebp
  int v7; // ebx
  int v8; // er8
  int v9; // er10
  bool result; // al
  int v11; // [rsp+0h] [rbp-38h]

  v1 = a1[1];
  v2 = *a1;
  v3 = a1[2];
  v4 = a1[3];
  v5 = a1[4];
  v6 = a1[6];
  v7 = a1[5];
  v8 = a1[7];
  v9 = a1[8];
  result = 0;
  if ( -85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613 )
  {
    v11 = a1[9];
    if ( 30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400
      && -103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 << 6) - 120 * v9 == -10283
      && 71 * v6 + (v7 << 7) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855
      && 5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944
      && -54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222
      && -83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258
      && 81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559
      && 101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308 )
    {
      result = 99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697;
    }
  }
  return result;
}
```

- 直接上z3

```python
from z3 import *
v1 = Int('v1')
v2 = Int('v2')
v3 = Int('v3')
v4 = Int('v4')
v5 = Int('v5')
v6 = Int('v6')
v7 = Int('v7')
v8 = Int('v8')
v9 = Int('v9')
v10 = Int('v10')
v11 = Int('v11')
s = z3.Solver()
s.add(-85 * v9 + 58 * v8 + 97 * v6 + v7 + -45 * v5 + 84 * v4 + 95 * v2 - 20 * v1 + 12 * v3 == 12613)
s.add(30 * v11 + -70 * v9 + -122 * v6 + -81 * v7 + -66 * v5 + -115 * v4 + -41 * v3 + -86 * v1 - 15 * v2 - 30 * v8 == -54400)
s.add(-103 * v11 + 120 * v8 + 108 * v7 + 48 * v4 + -89 * v3 + 78 * v1 - 41 * v2 + 31 * v5 - (v6 * 64) - 120 * v9 == -10283)
s.add(71 * v6 + (v7 * 128) + 99 * v5 + -111 * v3 + 85 * v1 + 79 * v2 - 30 * v4 - 119 * v8 + 48 * v9 - 16 * v11 == 22855)
s.add(5 * v11 + 23 * v9 + 122 * v8 + -19 * v6 + 99 * v7 + -117 * v5 + -69 * v3 + 22 * v1 - 98 * v2 + 10 * v4 == -2944)
s.add(-54 * v11 + -23 * v8 + -82 * v3 + -85 * v2 + 124 * v1 - 11 * v4 - 8 * v5 - 60 * v7 + 95 * v6 + 100 * v9 == -2222)
s.add(-83 * v11 + -111 * v7 + -57 * v2 + 41 * v1 + 73 * v3 - 18 * v4 + 26 * v5 + 16 * v6 + 77 * v8 - 63 * v9 == -13258)
s.add(81 * v11 + -48 * v9 + 66 * v8 + -104 * v6 + -121 * v7 + 95 * v5 + 85 * v4 + 60 * v3 + -85 * v2 + 80 * v1 == -1559)
s.add(101 * v11 + -85 * v9 + 7 * v6 + 117 * v7 + -83 * v5 + -101 * v4 + 90 * v3 + -28 * v1 + 18 * v2 - v8 == 6308)
s.add(99 * v11 + -28 * v9 + 5 * v8 + 93 * v6 + -18 * v7 + -127 * v5 + 6 * v4 + -9 * v3 + -93 * v1 + 58 * v2 == -1697)
s.check()
print(s.model())
```

- ida里的数据顺序很乱，手动调整一下

```python
v = [0] * 10
v[1] = 48
v[6] = 95
v[0] = 70
v[3] = 82
v[9] = 64
v[2] = 117
v[4] = 84
v[5] = 121
v[8] = 119
v[7] = 55
for i in v:
    print(chr(i), end="")
#F0uRTy_7w@
```

- 拿到key，运行程序输入key拿到flag
  
  ## Crack me

- 集合了各种反调试的一道题

- main函数

```c
int wmain()
{
  FILE *v0; // eax
  FILE *v1; // eax
  char v3; // [esp+3h] [ebp-405h]
  char v4; // [esp+4h] [ebp-404h] BYREF
  char v5[255]; // [esp+5h] [ebp-403h] BYREF
  char Format; // [esp+104h] [ebp-304h] BYREF
  char v7[255]; // [esp+105h] [ebp-303h] BYREF
  char passwd; // [esp+204h] [ebp-204h] BYREF
  char v9[255]; // [esp+205h] [ebp-203h] BYREF
  char user; // [esp+304h] [ebp-104h] BYREF
  char v11[255]; // [esp+305h] [ebp-103h] BYREF

  printf("Come one! Crack Me~~~\n");
  user = 0;
  memset(v11, 0, sizeof(v11));
  passwd = 0;
  memset(v9, 0, sizeof(v9));
  while ( 1 )
  {
    do
    {
      do
      {
        printf("user(6-16 letters or numbers):");
        scanf("%s", &user);
        v0 = (FILE *)sub_CD24BE();
        fflush(v0);
      }
      while ( !(unsigned __int8)sub_CD1000(&user) );
      printf("password(6-16 letters or numbers):");
      scanf("%s", &passwd);
      v1 = (FILE *)sub_CD24BE();
      fflush(v1);
    }
    while ( !(unsigned __int8)sub_CD1000(&passwd) );
    sub_CD1090(&user);
    Format = 0;
    memset(v7, 0, sizeof(v7));
    v4 = 0;
    memset(v5, 0, sizeof(v5));
    v3 = ((int (__cdecl *)(char *, char *))loc_CD11A0)(&Format, &v4);
    if ( sub_CD1830((int)&user, &passwd) )
    {
      if ( v3 )
        break;
    }
    printf(&v4);
  }
  printf(&Format);
  return 0;
}
```

- 先后输入用户名（welcomebeijing）和密码，每次输入过后有一个`sub_CD24BE`函数，动调发现对user和passwd都没影响，跳过即可

- 主要加密/判断在`sub_CD1830`函数

```c
bool __usercall sub_CD1830@<al>(int a1@<ebx>, char *user, const char *passwd)
{
  int v4; // [esp+18h] [ebp-22Ch]
  int v5; // [esp+1Ch] [ebp-228h]
  int j; // [esp+28h] [ebp-21Ch]
  unsigned int i; // [esp+30h] [ebp-214h]
  char v8; // [esp+36h] [ebp-20Eh]
  char v9; // [esp+37h] [ebp-20Dh]
  char v10; // [esp+38h] [ebp-20Ch]
  unsigned __int8 v11; // [esp+39h] [ebp-20Bh]
  unsigned __int8 v12; // [esp+3Ah] [ebp-20Ah]
  char v13; // [esp+3Bh] [ebp-209h]
  int check; // [esp+3Ch] [ebp-208h] BYREF
  char v15; // [esp+40h] [ebp-204h] BYREF
  char v16[255]; // [esp+41h] [ebp-203h] BYREF
  _BYTE v17[256]; // [esp+140h] [ebp-104h] BYREF

  v5 = 0;
  j = 0;
  v12 = 0;
  v11 = 0;
  v17[0] = 0;
  memset(&v17[1], 0, 0xFFu);
  v15 = 0;
  memset(v16, 0, sizeof(v16));
  v10 = 0;
  i = 0;
  v4 = 0;
  while ( i < strlen(passwd) )
  {
    if ( isdigit(passwd[i]) )
    {
      v9 = passwd[i] - 48;
    }
    else if ( isxdigit(passwd[i]) )
    {
      if ( *((_DWORD *)NtCurrentPeb()->SubSystemData + 3) == 2 )// 反调
        passwd[i] = 34;
      v9 = (passwd[i] | 0x20) - 87;
    }
    else
    {
      v9 = ((passwd[i] | 0x20) - 97) % 6 + 10;
    }
    __rdtsc();
    __rdtsc();
    v10 = v9 + 16 * v10;
    if ( !((int)(i + 1) % 2) )
    {
      *(&v15 + v4++) = v10;
      a1 = v4;
      v10 = 0;
    }
    ++i;
  }
  while ( j < 8 )
  {
    v11 += byte_CE6050[++v12];
    v13 = byte_CE6050[v12];
    v8 = byte_CE6050[v11];
    byte_CE6050[v11] = v13;
    byte_CE6050[v12] = v8;
    if ( ((int)NtCurrentPeb()->UnicodeCaseTableData & 0x70) == 0 )// 反调
      v13 = v11 + v12;
    v17[j] = byte_CE6050[(unsigned __int8)(v8 + v13)] ^ *(&v15 + v5);
    if ( !(unsigned __int8)*(_DWORD *)&NtCurrentPeb()->BeingDebugged )// 反调
    {
      v11 = -83;
      v12 = 43;
    }
    sub_CD1710((int)v17, user, j++);
    v5 = j;
    if ( j >= (unsigned int)(&v15 + strlen(&v15) + 1 - v16) )
      v5 = 0;
  }
  check = 0;
  sub_CD1470(a1, v17, &check);
  return check == 0xAB94;
}
```

- 从上到下总共三次反调试操作，上面已经是patch过的版本（对应汇编jz与jnz互改）

- 上面一个while循环实现了从字符串数据中获得原本字符值，具体可动调试试

- 下面加密部分大致可分为3块，下面倒着分析

- 第一块

- 整个函数最后返回验证的是`check`值，而check值应由`sub_CD1470`获得

- `sub_CD1470`函数

```c
void __usercall sub_CD1470(int a1@<ebx>, _BYTE *v17, _DWORD *check)
{
  char v5; // al

  if ( *v17 != 'd' )
    *check ^= 3u;
  else
    *check |= 4u;
  if ( v17[1] != 'b' )
  {
    *check &= 0x61u;
    _EAX = (_DWORD *)*check;
  }
  else
  {
    _EAX = check;
    *check |= 20u;
  }
  __asm { aam }
  if ( v17[2] != 'a' )
    *check &= 0xAu;
  else
    *check |= 0x84u;
  if ( v17[3] != 'p' )
    *check >>= 7;
  else
    *check |= 0x114u;
  if ( v17[4] != 'p' )
    *check *= 2;
  else
    *check |= 0x380u;
  if ( *((_DWORD *)NtCurrentPeb()->SubSystemData + 3) != 2 )// 反调
  {
    if ( v17[5] != 'f' )
      *check |= 0x21u;
    else
      *check |= 0x2DCu;
  }
  if ( v17[5] != 's' )
  {
    v5 = (char)check;
    *check ^= 0x1ADu;
  }
  else
  {
    *check |= 0xA04u;
    v5 = (char)check;
  }
  _AL = v5 - (~(a1 >> 5) - 1);
  __asm { daa }
  if ( v17[6] != 'e' )
    *check |= 0x4Au;
  else
    *check |= 0x2310u;
  if ( v17[7] != 'c' )
    *check &= 0x3A3u;
  else
    *check |= 0x8A10u;
}
```

- 可见有意义字符串`dbappsec`，把check异或上相应的值正好是验证所需的0xab94，由此可得到v17的值

- 第二块

- 倒退上去是`sub_CD1710`函数

```c
void __cdecl sub_CD1710(int a1, const char *a2, signed int a3)
{
  signed int v3; // [esp+4h] [ebp-58h]
  struct _STARTUPINFOW StartupInfo; // [esp+14h] [ebp-48h] BYREF

  memset(&StartupInfo, 0, sizeof(StartupInfo));
  StartupInfo.cb = 68;
  GetStartupInfoW(&StartupInfo);
  v3 = strlen(a2);
  if ( !StartupInfo.dwX
    && !StartupInfo.dwY
    && !StartupInfo.dwXCountChars
    && !StartupInfo.dwYCountChars
    && !StartupInfo.dwFillAttribute
    && !StartupInfo.dwXSize
    && !StartupInfo.dwYSize )
  {
    if ( a3 <= v3 )
      *(_BYTE *)(a3 + a1) ^= a2[a3];
    else
      *(_BYTE *)(a3 + a1) += byte_CE6050[v3 + a3] & a2[v3];
  }
}
```

- 首先下面第二个if else中的else一定不会被执行，因为a3不可能大于v3，具体依赖参数分析

- 第一个if内的条件又是个反调（（

- 参考[简单反调试和花指令 | BMooS](https://bmoos.github.io/2020/10/26/%E5%8F%8D%E8%B0%83%E8%AF%95%E5%92%8C%E8%8A%B1%E6%8C%87%E4%BB%A4/)

- > ```c
  > BOOL CheckDebug() {  
  >     STARTUPINFO si;  
  >     GetStartupInfo(&si);  
  >     if (si.dwFlags!=1 || si.dwX!=0 || si.dwY!=0 || si.dwXSize!=0 || si.dwYSize!=0 || si.dwXCountChars!=0 || si.dwYCountChars!=0 || si.dwFillAttribute!=0) {  
  >         return TRUE;  
  >     }  
  >     else {  
  >         return FALSE;  
  >     } 
  > }
  > ```

- 按说题目给的if判断应该是正常情况下（不在调试）满足if条件，进行异或

- 但这却是问题所在，要得到buu平台上的flag不能进这个异或，是buu出了问题？还是有什么更大的坑？暂时不得而知

- 第三块

```c
    v11 += byte_CE6050[++v12];
    v13 = byte_CE6050[v12];
    v8 = byte_CE6050[v11];
    byte_CE6050[v11] = v13;
    byte_CE6050[v12] = v8;
    if ( ((int)NtCurrentPeb()->UnicodeCaseTableData & 0x70) == 0 )// 反调
      v13 = v11 + v12;
    v17[j] = byte_CE6050[(unsigned __int8)(v8 + v13)] ^ *(&v15 + v5);
```

- 由以上两步拿到了v17的值，这一步是要得到v15的值

- 如何得到`byte_CE6050[(unsigned __int8)(v8 + v13)]`的值是关键

- `unsigned __int8`的强制类型转换确保数组下标在0-255（8位）

- 可行的方案理论上有两种
  
  - 动调到循环开始dump下来byte_CE6050的值，然后把整个代码dump下来跑一遍，但由于担心在我没注意的地方byte_CE6050被修改，我选择了第二种方法
  
  - 纯动调取值，这里遇到的麻烦是ida里调试的时候无法直接查看表达式的值，需要自己去找比较麻烦，但能确保数据正确

- 最后得到的8个值`key = [0x2a,0xd7,0x92,0xe9,0x53,0xe2,0xc4,0xcd]`

- 脚本

```python
from hashlib import md5
user = "welcomebeijing"
v17 = "dbappsec"
passwd = ""
v = [0] * 8

#for i in range(8):    //这就是上面所说第二步的问题
#    v[i] = ord(v17[i]) ^ ord(user[i])
key = [0x2a,0xd7,0x92,0xe9,0x53,0xe2,0xc4,0xcd]

for i in range(8):
    passwd += (hex(key[i] ^ ord(v17[i])).replace("0x",""))
print(passwd)
md5 = md5()
md5.update(passwd.encode("utf-8"))
print(md5.hexdigest())
```

- 不加第二步时输出buu平台可过的`flag{d2be2981b84f2a905669995873d6a36c}`
  
  ## 特殊的base64

- main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  char v6[16]; // [rsp+20h] [rbp-60h] BYREF
  char v7[16]; // [rsp+30h] [rbp-50h] BYREF
  char input[15]; // [rsp+40h] [rbp-40h] BYREF
  char v9; // [rsp+4Fh] [rbp-31h] BYREF
  char v10[32]; // [rsp+50h] [rbp-30h] BYREF

  _main(argc, argv, envp);
  std::string::string((std::string *)input);
  std::allocator<char>::allocator(&v9);
  std::string::string(v7, "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI==", &v9);
  std::allocator<char>::~allocator(&v9);
  v3 = std::operator<<<std::char_traits<char>>(refptr__ZSt4cout, "Please input your flag!!!!");
  std::ostream::operator<<(v3, refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
  std::operator>><char>(refptr__ZSt3cin, (std::string *)input);
  std::string::string((std::string *)v10, (const std::string *)input);
  base64Encode(v6, v10);
  std::string::~string((std::string *)v10);
  if ( (unsigned __int8)std::operator==<char>(v6, v7) )
    v4 = std::operator<<<std::char_traits<char>>(refptr__ZSt4cout, "The flag is right!!!!!!!!!");
  else
    v4 = std::operator<<<std::char_traits<char>>(refptr__ZSt4cout, "This is a wrong flag!!!!!!!!");
  std::ostream::operator<<(v4, refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
  std::string::~string((std::string *)v6);
  std::string::~string((std::string *)v7);
  std::string::~string((std::string *)input);
  return 0;
}
```

- 还是base64换表，直接上脚本吧

```python
import base64
standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
new_table = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0987654321/+"
enc = "mTyqm7wjODkrNLcWl0eqO8K8gc1BPk1GNLgUpI=="
table = str.maketrans(new_table, standard_table)
print(base64.b64decode(enc.translate(table)))
```

- b'flag{Special_Base64_By_Lich}'
  
  ## [WUSTCTF2020]level4

- 这道题是个体力活

- main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("Practice my Data Structure code.....");
  puts("Typing....Struct.....char....*left....*right............emmmmm...OK!");
  init();
  puts("Traversal!");
  printf("Traversal type 1:");
  midTraversal((char *)&node_23_root);
  printf("\nTraversal type 2:");
  lastTraversal((char *)&node_23_root);
  printf("\nTraversal type 3:");
  puts("    //type3(&x[22]);   No way!");
  puts(&byte_400A37);
  return 0;
}
```

- 已知二叉树的中序遍历和后序遍历（运行即可得到），求先序遍历

```
2f0t02T{hcsiI_SwA__r7Ee}
20f0Th{2tsIS_icArE}e7__w
```

- 但由于中间有重复字符，搞了一会没搞出来，转而去看init函数，即二叉树的构建过程，这里需要手动修一下结构体，最终效果

```c
void init()
{
  int i; // [rsp+Ch] [rbp-34h]
  char v1[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  strcpy(v1, "I{_}Af2700ih_secTS2Et_wr");
  for ( i = 0; i <= 23; ++i )
    *((_BYTE *)&node_1.val + 24 * i) = v1[i];
  node_23_root.left = &node_16;
  node_16.left = &node_21;
  node_21.left = &node_6;
  node_6.left = &node_7;
  node_6.right = &node_9;
  node_21.right = &node_19;
  node_19.left = &node_10;
  node_19.right = &node_2;
  node_2.left = &node_17;
  node_2.right = &node_12;
  node_16.right = &node_11;
  node_11.left = &node_14;
  node_11.right = &node_3;
  node_3.left = &node_1;
  node_3.right = &node_18;
  node_23_root.right = &node_22;
  node_22.left = &node_5;
  node_22.right = &node_13;
  node_13.right = &node_8;
  node_8.left = &node_24;
  node_8.right = &node_15;
  node_15.left = &node_20;
  node_15.right = &node_4;
}
```

- 结构体如下，val的大小可以观察一下汇编中的数据得到

```c
struct Tree
{
  __int64 val;
  Tree *left;
  Tree *right;
};
```

- 根据只有左右节点，没有父节点的特点可以确定23号为root

- 然后建立整棵树

```
                  w/23
          c/16             _/22
     t/21         i/11     A/5    _/13
  f/6      2/19  s/14   _3             78
2/7  0/9  0/10  {/2     I/1 S/18        r/24   e/15
            T/17 h/12                   E/20   }/4
```

- 先序遍历走一下拿到flag`wctf2020{This_IS_A_7reE}`
  
  ## [网鼎杯 2020 青龙组]singal

- 主要函数如下

```c
void __cdecl vm_operad(int *a1, int const_114)
{
  char flag[200]; // [esp+13h] [ebp-E5h] BYREF
  char v3; // [esp+DBh] [ebp-1Dh]
  int v4; // [esp+DCh] [ebp-1Ch]
  int v5; // [esp+E0h] [ebp-18h]
  int v6; // [esp+E4h] [ebp-14h]
  int flag_cnt; // [esp+E8h] [ebp-10h]
  int a1_cnt; // [esp+ECh] [ebp-Ch]

  a1_cnt = 0;
  flag_cnt = 0;
  v6 = 0;
  v5 = 0;
  v4 = 0;
LABEL_2:
  while ( a1_cnt < const_114 )
  {
    switch ( a1[a1_cnt] )
    {
      case 1:
        flag[v5 + 100] = v3;
        ++a1_cnt;
        ++v5;
        ++flag_cnt;
        break;
      case 2:
        v3 = a1[a1_cnt + 1] + flag[flag_cnt];
        a1_cnt += 2;
        break;
      case 3:
        v3 = flag[flag_cnt] - LOBYTE(a1[a1_cnt + 1]);
        a1_cnt += 2;
        break;
      case 4:
        v3 = a1[a1_cnt + 1] ^ flag[flag_cnt];
        a1_cnt += 2;
        break;
      case 5:
        v3 = a1[a1_cnt + 1] * flag[flag_cnt];
        a1_cnt += 2;
        break;
      case 6:
        ++a1_cnt;
        break;
      case 7:
        if ( flag[v6 + 100] != a1[a1_cnt + 1] )
        {
          printf("what a shame...");
          exit(0);
        }
        ++v6;
        a1_cnt += 2;
        break;
      case 8:
        flag[v4] = v3;
        ++a1_cnt;
        ++v4;
        break;
      case 10:
        read(flag);
        ++a1_cnt;
        break;
      case 11:
        v3 = flag[flag_cnt] - 1;
        ++a1_cnt;
        break;
      case 12:
        v3 = flag[flag_cnt] + 1;
        ++a1_cnt;
        break;
      default:
        goto LABEL_2;
    }
  }
}
```

- a1是前面初始化时生成的一个表，可以看出全程不会改变

- 变量值都是已知的，求flag

- 目的简单明确，把它逆了，但有很多细节问题

- 1. a1里存的并非全是操作数，有些是需要参与运算的值，上一步的操作决定步长（即下一步的操作），逆过来的时候无法判断步长(即a1_cnt是减1还是减2)
  
  2. v3，v4，v5，v6的结束值即逆写的初值需要确定
  
  3. default里goto label_2需要明白其实没啥用

- 针对以上解决方案（可能不是最优

- 1. 所有操作后步长(a1_cnt)均设置成最小步长-1，然后加一个判断，是否是真正的操作数，不是的话再a1_cnt-1
  
  2. v3分析一下会发现运行时会先被赋值后进行运算，所以无需初值。至于v4，v5，v6，这几个得自己数一遍，如果只是遍历一遍看进哪个case可能会把非操作数算上，还好数量不太大，最后数出来三个数都是15
  
  3. 至于default正常运行是不会进去的，忽略即可

- 最后贴出脚本，调试了好久才出，写得有点繁琐但不想改了（（

```c
#include <stdio.h>

unsigned int a1[] = {};//这就是动调dump下来的a1数组，但太长了粘不下来
int a1_cnt = 112;
int flag_cnt = 15;
int v6 = 15;
int v5 = 15;
int v4 = 15;
int const_114 = 114;
unsigned char flag[200];
unsigned char v3;

int main()
{

    while (a1_cnt >= 0)
    {
        if (a1[a1_cnt - 1] >= 2 && a1[a1_cnt - 1] <= 5)
        {   // 这么判断可能换个数据就能卡掉，但显然这已经能拿到flag了
            a1_cnt--;
            // 5 3 8 特判
            if (a1[a1_cnt - 1] >= 2 && a1[a1_cnt - 1] <= 5 && a1[a1_cnt + 1] <= 12)
                a1_cnt++;
        }

        switch (a1[a1_cnt])
        {
        case 1:
            --flag_cnt;
            --v5;
            --a1_cnt;
            v3 = flag[v5 + 100];
            break;
        case 2:
            flag[flag_cnt] = v3 - a1[a1_cnt + 1];
            a1_cnt--;
            break;
        case 3:
            flag[flag_cnt] = v3 + (a1[a1_cnt + 1] & 0x0000ffff);
            a1_cnt--;
            break;
        case 4:
            flag[flag_cnt] = v3 ^ a1[a1_cnt + 1];
            a1_cnt--;
            break;
        case 5:
            flag[flag_cnt] = v3 / a1[a1_cnt + 1];
            a1_cnt--;
            break;
        case 6:
            --a1_cnt;
            break;
        case 7:
            --v6;
            flag[v6 + 100] = a1[a1_cnt + 1];
            a1_cnt--;
            break;
        case 8:
            --v4;
            --a1_cnt;
            v3 = flag[v4];
            break;
        case 10:
            puts(flag);
        case 11:
            --a1_cnt;
            flag[flag_cnt] = v3 + 1;
            break;
        case 12:
            --a1_cnt;
            flag[flag_cnt] = v3 - 1;
            break;
        default:
            a1_cnt--;
        }
    }
}
```

- `flag{757515121f3d478}`
  
  ## [GUET-CTF2019]number_game

- 第二次做这题了，发现了种非预期解（

- main函数

```c
unsigned __int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v4; // [rsp+8h] [rbp-38h]
  __int64 input; // [rsp+10h] [rbp-30h] BYREF
  __int16 v6; // [rsp+18h] [rbp-28h]
  char a1a[8]; // [rsp+20h] [rbp-20h] BYREF
  __int16 v8; // [rsp+28h] [rbp-18h]
  char v9; // [rsp+2Ah] [rbp-16h]
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  input = 0LL;
  v6 = 0;
  *(_QWORD *)a1a = 0LL;
  v8 = 0;
  v9 = 0;
  __isoc99_scanf("%s", &input);
  if ( (unsigned int)check_len((const char *)&input) )
  {
    v4 = sub_400758((char *)&input, 0, 10u);
    sub_400807(v4, a1a);
    v9 = 0;
    copy(a1a);
    if ( (unsigned int)sub_400917() )
    {
      puts("TQL!");
      printf("flag{");
      printf("%s", (const char *)&input);
      puts("}");
    }
    else
    {
      puts("your are cxk!!");
    }
  }
  return __readfsqword(0x28u) ^ v10;
}
```

- sub_400758

```c
char *__fastcall sub_400758(char *input, int const_0, unsigned int len_input)
{
  char v5; // [rsp+1Fh] [rbp-11h]
  char *v6; // [rsp+28h] [rbp-8h]

  v5 = input[const_0];
  if ( v5 == ' ' || v5 == '\n' || const_0 >= (int)len_input )
    return 0LL;
  v6 = (char *)malloc(0x18uLL);
  *v6 = v5;
  *((_QWORD *)v6 + 1) = sub_400758(input, 2 * const_0 + 1, len_input);
  *((_QWORD *)v6 + 2) = sub_400758(input, 2 * (const_0 + 1), len_input);
  return v6;
}
```

- sub_400807

```c
void __fastcall sub_400807(char *a1, char *a2)
{
  if ( a1 )
  {
    sub_400807(*((char **)a1 + 1), a2);
    a2[dword_601080++] = *a1;
    sub_400807(*((char **)a1 + 2), a2);
  }
}
```

- copy

```c
void __fastcall sub_400881(char *a1)
{
  byte_601060[2] = *a1;
  byte_601060[7] = a1[1];
  byte_601060[9] = a1[2];
  byte_601060[11] = a1[3];
  byte_601060[14] = a1[4];
  byte_601060[15] = a1[5];
  byte_601060[17] = a1[6];
  byte_601060[18] = a1[7];
  byte_601060[22] = a1[8];
  byte_601060[23] = a1[9];
}
```

- sub_400917

```c
__int64 sub_400917()
{
  unsigned int v1; // [rsp+0h] [rbp-10h]
  int i; // [rsp+4h] [rbp-Ch]
  int j; // [rsp+8h] [rbp-8h]
  int k; // [rsp+Ch] [rbp-4h]

  v1 = 1;
  for ( i = 0; i <= 4; ++i )
  {
    for ( j = 0; j <= 4; ++j )
    {
      for ( k = j + 1; k <= 4; ++k )
      {
        if ( byte_601060[5 * i + j] == byte_601060[5 * i + k] )
          v1 = 0;
        if ( byte_601060[5 * j + i] == byte_601060[5 * k + i] )
          v1 = 0;
      }
    }
  }
  return v1;
}
```

- 从后往前看，`sub_400917`函数结合`byte_601060`发现是个5*5的数独，手动填一下

```
 1 4 #0 2 3
 3 0 #4 1 #2
 0 #1 2 3 #4
#2 3 #1 #4 0
 4 2 #3 #0 1
```

- 得到了主函数中的`a1a` `0421421430`

- 上面两个函数，将input逐层建了一个二叉树，然后再中序遍历赋值给`ala`

- 正常做法是根据得到的`ala`即中序遍历建树，由于树从左到右生长，确保了答案的唯一性，这是我第一次做的时候的做法，如图

```c
       1
    1     3
  4   2  4  0
0  2  4
//flag：1134240024
```

- 这次做突然有个大胆的想法，算法只是改变了数字的顺序，那么可不可能会在几次改变顺序后循环呢？于是有了以下尝试，每次将上一次动调得到的改变后的数组当作下一次的输入，幸运的是，第6次过后我就获得了成功，数据如下

```c
0421421430
4134040221
2421104430
4134012024
0421404132
1134240024
0421421430
```

- 没有严谨的证明，但这确实不失为一种很高效的非预期解

- `flag{1134240024}`

