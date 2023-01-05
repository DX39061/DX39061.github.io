# buu misc wp


## 金三胖

- 下载附件是个gif

- 用gimp打开查看每一帧，其中夹杂着`flag{he11ohongke}`

## 二维码

- 附件是个二维码，扫描出文字`secret is here`

- binwalk扫一下

```
↪  binwalk ./QR_code.png                                                       2022年 03月 28日 星期一 22:15:42 CST

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 280 x 280, 1-bit colormap, non-interlaced
471           0x1D7           Zip archive data, encrypted at least v2.0 to extract, compressed size: 29, uncompressed size: 15, name: 4number.txt
650           0x28A           End of Zip archive, footer length: 22
```

- binwalk -d分不出来

- foremost分离发现一个加密的压缩包

- kali利用john解密

```shell
zip2john ./00000000.zip  > passwd.txt
john passwd.txt
```

- 得到密码7639

- 解压压缩包得到txt文件即可看到flag`CTF{vjpw_wnoei}`

## 你竟然赶我走

- 附件是一张jpg文件

- 用010查看二进制文件拉到最后即可看到flag`flag{stego_is_s0_bor1ing}`

## N种方法解决

- 附件为`key.exe`，010打开发现是base64字符串
- 在线网站转换成png图片，发现是二维码
- 扫码得flag`KEY{dca57f966e4e4e31fd5b15417da63269}`

## 大白

- 附件是一张打不开的图片

- 原因是出题人改了图片高使crc校验码检查出错

- 脚本爆破出图片高

```python
#!/usr/bin/env python
import struct
import binascii
import os
#根据PNG crc校验码爆破出图片宽度、高度
fi=open('./dabai.png','rb').read()

#12-15字节代表固定的文件头数据块的标示，16-19字节代表宽度，20-23字节代表高度，24-28字节分别代表
# Bit depth、ColorType、Compression method、Filter method、Interlace method
#29-32字节为CRC校验和

for i in range(10000):
    #pack函数将int转为bytes,>表示大端00 00 00 02,I表示4字节无符号int;<表示小端 02 00 00 00
    data=fi[12:20]+struct.pack('>I',i)+fi[24:29]  
    #byte的大小为8bits而int的大小为32bits,转换时进行与运算避免补码问题0x932f8a6b
    crc=binascii.crc32(data)&0xffffffff 
    #解开为无符号整数
    if crc==struct.unpack('>I',fi[29:33])[0]&0xffffffff :
        print(hex(i))
```

- 0x1df

- 用010修改图片高即可正确显示图片

- flag`flag{He1l0_d4_ba1}`

## 基础破解

- 压缩包加密，提示4位密码，直接用rarcrack爆破

- kali上装的rarcrack有问题，原因不明，arch上又装了一个，成功爆出密码`2593`

- 解压得flag.txt，base64解码得flag

## 乌镇峰会种图

- `Stegsolve`打开，找到analyze->file format，即可看到flag`flag{97314e7864a8f6262 7b26f3f998c37f1}`

## 文件中的秘密

- Gwenview打开图片，左边属性有一项`Windows Comment` ，值为flag，windows平台直接查看属性->备注应该就能看到

## wireshark

- 附件为一段流量包，要求找到登陆的passwd

- wireshark打开，过滤`http.request.method==POST`即可找到登陆语句

- `flag{ffb7567a1d4f4abdffdb54e022f8facd}`

## LSB

- 附件是一张图片，用stegsolve打开
- data extract rgb选都选0，dump下来发现是个二维码，扫码即可拿到flag

## rar

- 加密压缩包，提示4位纯数字，rarcrack直接爆

- 得到密码8795

- `flag{1773c5da790bd3caff38e3decd180eb7}`

## zip伪加密

- 粘一篇[知乎文章](https://zhuanlan.zhihu.com/p/399456259)，详细介绍了zip的结构，这一点用010打开会看得十分清晰

- 把第0x47位改成00即可修正伪加密

- 解压即可拿到flag

