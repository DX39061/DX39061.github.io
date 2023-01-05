# NepnepxCatCTF Reverse CatFly WriteUp


挺有意思的一道题，本身不算难，但最后加上我只有4解还是挺惊讶

题目是个命令行小游戏，运行起来可以看到屏幕的第一行会一直打印一些字符，但仔细看都是乱码

伪代码内容比较清晰，大段都是关于命令行参数、不同终端的处理之类的东西，重点内容如下：

```c
 while ( v13 )
  {
    if ( dword_E104 )
      printf("\x1B[H");
    else
      printf("\x1B[u");
    for ( screen_row = top; screen_row < bottom; ++screen_row )
    {
      for ( screen_col = left; screen_col < right; ++screen_col )
      {
        if ( screen_row <= 23 || screen_row > 42 || screen_col >= 0 )
        {
          if ( screen_col >= 0 && (unsigned int)screen_row <= 0x3F && screen_col <= 63 )
          {
            v19 = screen[screen_cnt][screen_row][screen_col];
            off_FA88 = sub_6314((unsigned int)screen_cnt, screen_row, screen_col, (__int64)v12);
          }
          else
          {
            v19 = 44;
          }
        }
        else
        {
          v18 = (2 - screen_col) % 16 / 8;
          if ( ((screen_cnt >> 1) & 1) != 0 )
            v18 = 1 - v18;
          s[128] = (__int64)",,>>&&&+++###==;;;,,";
          v19 = asc_BFE3[v18 - 23 + screen_row];
          if ( !v19 )
            v19 = 44;
        }
        if ( v25 )
        {
          printf("%s", *((const char **)&unk_FCC0 + v19));
        }
        else if ( v19 == v22 || !*((_QWORD *)&unk_FCC0 + v19) )
        {
          printf("%s", off_FA88);
        }
        else
        {
          v22 = v19;
          printf("%s%s", *((const char **)&unk_FCC0 + v19), off_FA88);
        }
      }
      sub_65E2(1LL);
    }
    if ( dword_E100 )
    {
      time(&time1);
      v11 = difftime(time1, timer);
      v10 = sub_63FF((unsigned int)(int)v11);
      for ( n = (dword_E1FC - 29 - v10) / 2; n > 0; --n )
        putchar(' ');
      key += printf("\x1B[1;37mYou have nyaned for %d times!\x1B[J\x1B[0m", (unsigned int)++dword_108E0);
    }
    v22 = 0;
    ++frame_count;
    if ( frames && frame_count == frames )
      quit();
    if ( !screen[++screen_cnt] )
      screen_cnt = 0LL;
    usleep(1000 * v27);
  }
```

```c
char *__fastcall sub_6314(__int64 a1, int a2, int a3, __int64 a4)
{
  if ( a2 != 18 )
    return (char *)a4;
  if ( a3 <= 4 || a3 > 54 )
    return (char *)a4;
  byte1 = 32;
  enc[a3 - 5] ^= cal_key();
  if ( is_printable_char(enc[a3 - 5]) )
    byte2 = enc[a3 - 5] & 0x7F;
  else
    byte2 = 32;
  return &byte2;
}
```

```c
__int64 cal_key()
{
  key = 1103515245 * key + 12345;
  return (key >> 10) & 0x7FFF;
}
```

可以看出这就是更新屏幕显示内容的逻辑，我们关心的是第一行那一串字符，产生这些字符的逻辑在sub_6314，结合这个函数内的if限制可以得到，只有$screen\_row = 18 且 screen\_col \in [5, 54]$时才会真正产生字符，即画面中字符的位置

而字符的具体值是由`enc`数组和`key`的值计算而来的，结合hint说`要抄写这个算法跑一分钟就能出flag`，最终exp：

```c
#include <stdio.h>
#include <string.h>

unsigned int key = 0x1106;
unsigned int cal_key() {
    key = (0x41C64E6D * key + 12345) & 0xffffffff;
    return (((int)key >> 10) & 0x7fff);
}

int cal_digit(int num) {
    int digit = 0;
    while(num) {
        num /= 10;
        digit++;
    }
    return digit;
}

int main() {
    int cnt = 0;
    unsigned char flag[50];
    unsigned int enc[] = {
        0x27FB, 0x27A4, 0x464E, 0x0E36, 0x7B70, 0x5E7A, 0x1A4A, 0x45C1,
        0x2BDF, 0x23BD, 0x3A15, 0x5B83, 0x1E15, 0x5367, 0x50B8, 0x20CA,
        0x41F5, 0x57D1, 0x7750, 0x2ADF, 0x11F8, 0x09BB, 0x5724, 0x7374,
        0x3CE6, 0x646E, 0x010C, 0x6E10, 0x64F4, 0x3263, 0x3137, 0x00B8,
        0x229C, 0x7BCD, 0x73BD, 0x480C, 0x14DB, 0x68B9, 0x5C8A, 0x1B61,
        0x6C59, 0x5707, 0x09E6, 0x1FB9, 0x2AD3, 0x76D4, 0x3113, 0x7C7E,
        0x11E0, 0x6C70};
    while(1) {
        for (int i = 0; i < 50; i++) {
            enc[i] ^= cal_key(key);
            if (((enc[i] & 127) > 32) && ((enc[i] & 127) <= 126)) {
                flag[i] = enc[i] & 127;
            } else {
                flag[i] = ' ';
            }
        }
        if (!strncmp(flag, "CatCTF", 6)) {
            puts(flag);
            return 0;
        }
        cnt++;
        key += 41;    // key要加上printf的返回值
        key += cal_digit(cnt);
    }
}
```

为了节省运算时间，代码中做了一些省略，和计算字符串无关的代码，比如screen_row和screen_col的两个外层循环直接扬了

需要注意每次for循环结束之后，key的值要加上printf函数的返回值，即输出的字符数

踩到的另外一个坑：刚开始想法将所有字符输出到一个文件里，然后结合grep去找有用的字符串，理论可行，但一分钟跑出来就全是乱码，还以为是算法写得有问题。最后又尝试了一遍，程序一分半也没跑出结果，输出文件已经达到了4.7G，使用grep提示内存耗尽，文本编辑器尝试打开直接崩溃，还是挺吓人的，同时也可以看出如printf等输出函数对程序运行效率的降低非常大。

最终flag：`CatCTF{Fly1NG_NyAnC4t_Cha5eS_the_FL4G_in_The_Sky}`

