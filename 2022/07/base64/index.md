# 逆向人学密码（一）base64编码


# base64编码

## 编码原理

- Base64是一种基于64个`可打印字符`来表示`二进制数据`的表示方法
- 由于$\log_{2}{64}=6$，所以每6个比特为一个单元，对应一个可打印字符。3个字节即24个比特，对应4个Base64单元，故4个可打印字符表示3个字节的信息
- 如果被编码的字节数不能被3整除（多出1个或2个字节），那么先在末尾补1个或2个字节的0值，使其能够被3整除。然后进行base64编码，末尾每有6比特0值就在base64编码文本后加有一个‘’=‘’号

## 编码过程

- 定义base64编码对应表

- 计算编码后的文本长度

- 3个字节对应4个Base64单元进行编码

- 如果需要则补‘’=‘‘

## C语言实现

```c
unsigned char* base64_encode(unsigned char* str) {

    // 1. define the base64 table
    unsigned char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // 2. calculate the length of string after base64 encoding
    int str_len = strlen(str);
    int len;
    if (str_len % 3 == 0) {
        len = str_len / 3 * 4;
    }
    else {
        len = (str_len/3 + 1) * 4;
    }

    // 3. Encoding as a group of three 8-bit characters 
    unsigned char *res = malloc(sizeof(unsigned char) * len + 1);
    res[len] = '\0';

    int i, j;
    for(i=0, j=0; j<str_len; j+=3, i+=4) {
        res[i] = table[str[j] >> 2];
        res[i+1] = table[(str[j]&0b11) << 4 | str[j+1] >> 4];
        res[i+2] = table[(str[j+1]&0b1111) << 2 | str[j+2] >> 6];
        res[i+3] = table[str[j+2]&0b111111];
    }

    // 4. add '=' if needed
    switch (str_len % 3) {
        case 1:
            res[len-1] = '=';
            res[len-2] = '=';
            break;
        case 2:
            res[len-1] = '=';
            break;
    }
    return res;
}
```

## 逆向算法特征

- 将二进制文件拖入ida分析，能复原较为清晰的代码

```c
_BYTE *__fastcall base64_encode(const char *str)
{
  int len; // [rsp+18h] [rbp-68h]
  int v3; // [rsp+1Ch] [rbp-64h]
  int i; // [rsp+20h] [rbp-60h]
  int str_len; // [rsp+24h] [rbp-5Ch]
  _BYTE *res; // [rsp+28h] [rbp-58h]
  char table[72]; // [rsp+30h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+78h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  strcpy(table, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
  str_len = strlen(str);
  if ( str_len % 3 )
    len = 4 * (str_len / 3 + 1);
  else
    len = 4 * (str_len / 3);
  res = malloc(len + 1LL);
  res[len] = 0;
  v3 = 0;
  for ( i = 0; i < str_len; i += 3 )
  {
    res[v3] = table[(unsigned __int8)str[i] >> 2];
    res[v3 + 1] = table[((unsigned __int8)str[i + 1] >> 4) | (16 * str[i]) & 0x30];
    res[v3 + 2] = table[((unsigned __int8)str[i + 2] >> 6) | (4 * str[i + 1]) & 0x3C];
    res[v3 + 3] = table[str[i + 2] & 0x3F];
    v3 += 4;
  }
  if ( str_len % 3 == 1 )
  {
    res[len - 1] = '=';
    res[len - 2] = '=';
  }
  else if ( str_len % 3 == 2 )
  {
    res[len - 1] = '=';
  }
  return res;
}
```

- base64编码的显著特征在于编码表table，在逆向题中常见换表或动态生成表

- 编码过程中的循环移位操作也是一大特征

- 对len的判断也必不可少，是个突破点

