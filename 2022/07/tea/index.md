# 逆向人学密码（二）TEA


# TEA

## 算法简介

- TEA：**微型加密算法**（Tiny Encryption Algorithm，TEA）是一种易于描述和执行的块密码，通常只需要很少的代码就可实现。

- 块密码：在密码学中，**分组加密**（英语：**Block cipher**），又称**分块加密**或**块密码**，是一种对称密钥算法。它将明文分成多个等长的模块（block），使用确定的算法和对称密钥对每组分别加密解密。

## 算法属性

- TEA操作处理两个32位无符号整型上（可能源于一个64位数据）

- TEA使用一个128位密钥

## 算法过程

### - TEA遵循Feistel网络

![Feistel cipher diagram ensvg](https://upload.wikimedia.org/wikipedia/commons/thumb/f/fa/Feistel_cipher_diagram_en.svg/511px-Feistel_cipher_diagram_en.svg.png)

- Feistel网络构造细节：
  
  - 令F为轮函数，并令$K_0,K_1,……K_n$分别为0,1,……n的子密钥
  
  - 将明文拆分为两个等长的块，$(L_0,R_0)$
  
  - 对每轮$i=0,1……n$，计算
    
    $L_{i+1}=R_i$
    
    $R_{i+1}=L_i \bigoplus F(R_i,K_i)$
  
  - 则密文为$(R_{n+1},L_{n+1})$
  
  - 加解密过程唯一区别是子密钥顺序反转

### - TEA实现过程

![TEA InfoBox Diagrampng](https://upload.wikimedia.org/wikipedia/commons/a/a1/TEA_InfoBox_Diagram.png)

## C语言实现

```c
#include <stdint.h>

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```

## 逆向算法特征

- delta的值0x9e3779b9，且有sum在每一轮逐次累加，但delta数值容易被魔改

- 加密轮次一般为32轮，且每轮加密都是对两个32位数据进行

- `<<4`与`>>5`及其加密逻辑一般是最重要的突破口

## XTEA

![XTEA InfoBox Diagramsvg](https://upload.wikimedia.org/wikipedia/commons/thumb/a/ab/XTEA_InfoBox_Diagram.svg/300px-XTEA_InfoBox_Diagram.svg.png)

```c
#include <stdint.h>

/* take 64 bits of data in v[0] and v[1] and 128 bits of key[0] - key[3] */

void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}
```

## XXTEA

![Algorithm diagram for XXTEA ciphersvg](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d0/Algorithm_diagram_for_XXTEA_cipher.svg/391px-Algorithm_diagram_for_XXTEA_cipher.svg.png)

```c
#define MX ((z>>5^y<<2) + (y>>3^z<<4) ^ (sum^y) + (k[p&3^e]^z))

  long btea(long* v, long n, long* k) {
    unsigned long z=v[n-1], y=v[0], sum=0, e, DELTA=0x9e3779b9;
    long p, q ;
    if (n > 1) {          /* Coding Part */
      q = 6 + 52/n;
      while (q-- > 0) {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<n-1; p++) y = v[p+1], z = v[p] += MX;
        y = v[0];
        z = v[n-1] += MX;
      }
      return 0 ; 
    } else if (n < -1) {  /* Decoding Part */
      n = -n;
      q = 6 + 52/n;
      sum = q*DELTA ;
      while (sum != 0) {
        e = (sum >> 2) & 3;
        for (p=n-1; p>0; p--) z = v[p-1], y = v[p] -= MX;
        z = v[n-1];
        y = v[0] -= MX;
        sum -= DELTA;
      }
      return 0;
    }
    return 1;
  }
```

