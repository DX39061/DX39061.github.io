# 逆向人学密码（三）RC algorithms


# RC algorithms

RC algorithms 是由[Ron Rivest](https://en.wikipedia.org/wiki/Ron_Rivest "Ron Rivest")设计的一系列加密算法，在逆向中常见到的RC4属于其中的一个，下面引自维基百科

- RC1 was never published.
- [RC2](https://en.wikipedia.org/wiki/RC2 "RC2") was a 64-bit [block cipher](https://en.wikipedia.org/wiki/Block_cipher "Block cipher") developed in 1987.
- RC3 was broken before ever being used.
- [RC4](https://en.wikipedia.org/wiki/RC4 "RC4") is a [stream cipher](https://en.wikipedia.org/wiki/Stream_cipher "Stream cipher").
- [RC5](https://en.wikipedia.org/wiki/RC5 "RC5") is a 32/64/128-bit block cipher developed in 1994.
- [RC6](https://en.wikipedia.org/wiki/RC6 "RC6"), a 128-bit block cipher based heavily on RC5, was an [AES finalist](https://en.wikipedia.org/wiki/AES_process "AES process") developed in 1997.

## RC4

### 算法简介

RC4是一种流加密算法。所谓流加密，其核心思想是通过一系列算法生成较为随机的一串密钥流，然后将明文与密钥流异或得到密文，显然地，把密文再与密钥流异或即得到明文

RC4获得随机密钥流依靠特定的密钥key打乱S盒，换句话说，key一定时，生成的密钥流是确定的

### 算法属性

- RC4是一种流加密算法

- 密钥长度可变

- 加解密使用同样密钥，属于对称加密算法

### 算法过程

- 初始化S盒，一般是256个字节

- 使用密钥key打乱S盒

- 根据s盒生成密钥流

- 明文/密文与密钥流异或得到密文/明文

### python实现

- main函数

```python
def main():
    key = [1, 2, 3, 4, 5]        # 准备一些变量
    key_len = len(key)
    plain = "i_am_plain_text"
    plain_len = len(plain)
    cipher = [0] * plain_len

    s = [i for i in range(256)]    # 初始化s盒
    rc4_init(s, key, key_len)      # 使用key打乱s盒
    key_stream = rc4_generate_keystream(s[:], plain_len) # 生成密钥流

    for i in range(plain_len):     # 逐字节异或加密
        cipher[i] = ord(plain[i]) ^ key_stream[i]
```

- 使用key打乱s盒

```python
def rc4_init(s, key, key_len):
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i%key_len])%256
        tmp = s[i]
        s[i] = s[j]
        s[j] = tmp
```

- 生成密钥流（这里是按明文长度生成

```python
def rc4_generate_keystream(s, length):
    i = 0
    j = 0
    key_stream = []
    while length:
        i = (i + 1) % 256    # 可以保证每256次循环后s盒中的每个元素至少被交换一次
        j = (j + s[i]) % 256
        tmp = s[i]
        s[i] = s[j]
        s[j] = tmp
        key_stream.append(s[(s[i] + s[j]) % 256])
        length -= 1
    return key_stream
```

### 逆向算法特征

- 256字节、值分别是0-255的S盒

- 整个算法被分成两部分

- 打乱S盒时`j = (j + s[i] + key[i%key_len])%256`并不常见

## RC2

RC2可作为DES算法的建议替代算法。 它的输入和输出都是64比特。 密钥的长度是从1字节到128字节可变，但1998年的实现是8字节。此算法被设计为可容易地在16位的微处理器上实现。

to be continued...

## RC5

**RC5**是一种因简洁著称的对称分组加密算法。它是参数可变的分组密码算法，三个可变的参数是：分组大小、密钥大小和加密轮数。 在此算法中使用了三种运算：异或、加和循环。

to be continued...

## RC6

RC6是基于RC5的128位块加密算法，实际上是由3个参数确定的一个加密算法族。

to be continued...

