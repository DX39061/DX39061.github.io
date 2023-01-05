# 2022DASCTF X FATE RE Crackme wp


## Crackme

- 运行一下看图标知道是MFC

- 拖进ida搜索字符串`wrong`就能找到`事件处理函数`

```c
int __thiscall sub_1131E0(struct_this *this)
{
  const void *key_addr; // eax
  const void *flag_addr; // eax
  int result; // eax
  unsigned int key_len; // [esp+18h] [ebp-230h]
  size_t flag_len; // [esp+20h] [ebp-228h] BYREF
  void *md5_top_half_key; // [esp+24h] [ebp-224h] BYREF
  const void *md5_bottom_half_key; // [esp+28h] [ebp-220h] BYREF
  BYTE *v9; // [esp+2Ch] [ebp-21Ch] BYREF
  size_t dwDataLen; // [esp+30h] [ebp-218h] BYREF
  size_t v11; // [esp+34h] [ebp-214h] BYREF
  DWORD v12; // [esp+38h] [ebp-210h] BYREF
  BYTE flag[260]; // [esp+3Ch] [ebp-20Ch] BYREF
  BYTE key[260]; // [esp+140h] [ebp-108h] BYREF

  CWnd::UpdateData((CWnd *)this, 1);
  memset(key, 0, sizeof(key));
  memset(flag, 0, sizeof(flag));
  key_len = strlen(&this->gap4[212]);
  flag_len = strlen(&this->gap4[208]);
  dwDataLen = 0;
  v11 = 0;
  v12 = 0;
  key_addr = (const void *)sub_112590(&this->gap4[212], key_len);
  memmove(key, key_addr, key_len);
  flag_addr = (const void *)sub_112590(&this->gap4[208], flag_len);
  memmove(flag, flag_addr, flag_len);
  if ( key_len != 8 && flag_len != 32 )
    return wrong((CWnd *)this);
  hash_encode(key, key_len >> 1, 0x8003u, (int)&md5_top_half_key, (int)&dwDataLen);// md5
  hash_encode(&key[4], key_len >> 1, 0x8004u, (int)&md5_bottom_half_key, (int)&v11);// sha1
  hash_encode(key, key_len, 0x8003u, (int)&v9, (int)&v12);// md5
  memcmp(md5_top_half_key, &this->charDC, dwDataLen);
  if ( memcmp(md5_bottom_half_key, &this->char1E0, v11) )
    return wrong((CWnd *)this);
  md5_and_AES_encrypt(v9, v12, flag, &flag_len, 0x104u);
  if ( !memcmp(flag, &this->char2E4, flag_len) )
    result = success((CWnd *)this);
  else
    result = wrong((CWnd *)this);
  return result;
}
```

- 结合动调很容易搞清楚各个变量、函数的意义，但这里有个反调很难发现

- 参见[ZwSetInformationThread - CTF Wiki](https://ctf-wiki.org/reverse/windows/anti-debug/zwsetinformationthread/)

- 字符串里搜`ZwSetInformationThread`可找到这个函数

```c
int __thiscall sub_112E60(LPARAM *this)
{
  const CHAR *v1; // eax
  HMODULE v2; // eax
  HANDLE v3; // eax
  FARPROC ZwSetInformationThread; // [esp+8h] [ebp-24h]
  int i; // [esp+14h] [ebp-18h]
  int j; // [esp+14h] [ebp-18h]
  char v9[4]; // [esp+18h] [ebp-14h] BYREF
  int v10; // [esp+28h] [ebp-4h]

  CDialog::OnInitDialog((CDialog *)this);
  if ( sub_113AC0(0) )
  {
    sub_111CB0(4u);
    sub_112100(v9);
    v10 = 0;
    sub_113D40(101);
    if ( !std::string::empty((std::string *)v9) )
    {
      sub_113A60(0x800u, 0, 0);
      v1 = (const CHAR *)std::_Ptr_base<_EXCEPTION_RECORD const>::get(v9);
      sub_113A60(0, 0x10u, v1);
    }
    v10 = -1;
    sub_1129F0(v9);
  }
  sub_113A30(this[52], 1u);
  sub_113A30(this[52], 0);
  v2 = GetModuleHandleA("ntdll.dll");
  ZwSetInformationThread = GetProcAddress(v2, "ZwSetInformationThread");//反调
  v3 = GetCurrentThread();
  ((void (__stdcall *)(HANDLE, int, _DWORD, _DWORD))ZwSetInformationThread)(v3, 17, 0, 0);
  for ( i = 0; i < 16; ++i )
    *((_BYTE *)this + i + 220) ^= i;
  for ( j = 0; j < 20; ++j )
    *((_BYTE *)this + j + 480) ^= j;
  return 1;
}
```

- 并不是简单的调用了`windows`的系统函数，导致`import`窗口找不到，也增加了不少难度

- 具体绕过方法ctf-wiki也写的很清楚，不再赘述

- 结合重命名的函数应该能看得很清楚

- `hash_encode`函数

```c
bool __stdcall sub_113510(BYTE *pbData, DWORD dwDataLen, ALG_ID Algid, int a4, int a5)
{
  BYTE *v6; // [esp+10h] [ebp-20h]
  BOOL v7; // [esp+18h] [ebp-18h]
  BYTE v8[4]; // [esp+1Ch] [ebp-14h] BYREF
  DWORD pdwDataLen; // [esp+20h] [ebp-10h] BYREF
  HCRYPTPROV phProv; // [esp+24h] [ebp-Ch] BYREF
  HCRYPTHASH phHash; // [esp+28h] [ebp-8h] BYREF

  phProv = 0;
  phHash = 0;
  v6 = 0;
  *(_DWORD *)v8 = 0;
  pdwDataLen = 0;
  v7 = CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000);
  if ( v7 )
  {
    v7 = CryptCreateHash(phProv, Algid, 0, 0, &phHash);
    if ( v7 )
    {
      v7 = CryptHashData(phHash, pbData, dwDataLen, 0);
      if ( v7 )
      {
        pdwDataLen = 4;
        v7 = CryptGetHashParam(phHash, 4u, v8, &pdwDataLen, 0);
        if ( v7 )
        {
          v6 = (BYTE *)sub_114540(*(size_t *)v8);
          if ( v6 )
          {
            memset(v6, 0, *(size_t *)v8);
            v7 = CryptGetHashParam(phHash, 2u, v6, (DWORD *)v8, 0);
            if ( v7 )
            {
              *(_DWORD *)a4 = v6;
              *(_DWORD *)a5 = *(_DWORD *)v8;
            }
          }
          else
          {
            v7 = 0;
          }
        }
      }
    }
  }
  if ( !v7 && v6 )
    sub_11453B(v6);
  if ( phHash )
    CryptDestroyHash(phHash);
  if ( phProv )
    CryptReleaseContext(phProv, 0);
  return v7;
}
```

- 里面全是windows的API函数，重点看`Algid`参数，决定了hash的种类，具体参见[ALG_ID (Wincrypt.h) - Win32 apps | Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

- 即把8位的`key`分成2份，分别进行`md5`和`sha1`

- 比较的值可以动调取得，然后在线网站爆，这里推荐一下`https://crackstation.net/`，cmd5收费实在是太屑了

- 得到key`NocTuRne`

- 还剩一个`md5_and_AES_encrypt`函数对输入的`flag`加密

```c
bool __stdcall sub_1136E0(BYTE *pbData, DWORD dwDataLen, BYTE *a3, DWORD *pdwDataLen, DWORD dwBufLen)
{
  BOOL v6; // [esp+4h] [ebp-18h]
  HCRYPTKEY phKey; // [esp+Ch] [ebp-10h] BYREF
  HCRYPTPROV phProv; // [esp+10h] [ebp-Ch] BYREF
  HCRYPTHASH phHash; // [esp+14h] [ebp-8h] BYREF

  phProv = 0;
  phHash = 0;
  phKey = 0;
  v6 = CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000);
  if ( v6 )
  {
    v6 = CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash);
    if ( v6 )
    {
      v6 = CryptHashData(phHash, pbData, dwDataLen, 0);
      if ( v6 )
      {
        v6 = CryptDeriveKey(phProv, 0x660Eu, phHash, 1u, &phKey);
        if ( v6 )
          v6 = CryptEncrypt(phKey, 0, 1, 0, a3, pdwDataLen, dwBufLen);
      }
    }
  }
  if ( phKey )
    CryptDestroyKey(phKey);
  if ( phHash )
    CryptDestroyHash(phHash);
  if ( phProv )
    CryptReleaseContext(phProv, 0);
  return v6;
}
```

- 重点还是看`Algid`，`0x8003`对应`md5`，`0x660e`对应`AES`

- 由于windows的AES和一般的AES不太一样，纯逆很难，所以直接模拟整个函数的过程，调用windows的`CryptDecrypt`函数，其他照抄

- 此处ref：[DASCTF-FATE-Reverse | Hexo](https://gift1a.github.io/2022/04/23/DASCTF-FATE-Reverse/#more)

```c
#include <windows.h>
#include <windef.h>
#include <wincrypt.h>
#include<stdio.h>
int main()
{
    HCRYPTKEY phKey; // [esp+Ch] [ebp-10h] BYREF
    HCRYPTPROV phProv; // [esp+10h] [ebp-Ch] BYREF
    HCRYPTHASH phHash; // [esp+14h] [ebp-8h] BYREF
    BOOL retValue;

    BYTE flag_data[0x104] = { 0x5B, 0x9C, 0xEE, 0xB2, 0x3B, 0xB7, 0xD7, 0x34, 0xF3, 0x1B, 0x75, 0x14, 0xC6, 0xB2, 0x1F, 0xE8, 0xDE, 0x33, 0x44, 0x74, 0x75, 0x1B, 0x47, 0x6A, 0xD4, 0x37, 0x51, 0x88, 0xFC, 0x67, 0xE6, 0x60, 0xDA, 0x0D, 0x58, 0x07, 0x81, 0x43, 0x53, 0xEA, 0x7B, 0x52, 0x85, 0x6C, 0x86, 0x65, 0xAF, 0xB4 };
    BYTE keyBuf[] = { 0x5c,0x53,0xa4,0xa4,0x1d,0x52,0x43,0x7a,0x9f,0xa1,0xe9,0xc2,0x6c,0xa5,0x90,0x90 };
    DWORD dwDataLen = 0x10;
    DWORD dwBufLen = 0x104;
    DWORD dwDataLen_2;
    DWORD* pdwDataLen = &dwDataLen_2;
    *pdwDataLen = 0x20;


    phProv = 0;
    phHash = 0;
    phKey = 0;

    retValue = CryptAcquireContextA(&phProv, 0, 0, 0x18u, 0xF0000000);
    if (retValue)
    {
        retValue = CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash);
        if (retValue)
        {
            retValue = CryptHashData(phHash, keyBuf, dwDataLen, 0);
            if (retValue)
            {
                retValue = CryptDeriveKey(phProv, 0x660Eu, phHash, 1u, &phKey);
                if (retValue)
                    retValue = CryptDecrypt(phKey, 0, 1, 0, flag_data, pdwDataLen);
                printf("%s",retValue);
            }
        }
    }

    if (phKey)
        CryptDestroyKey(phKey);
    if (phHash)
        CryptDestroyHash(phHash);
    if (phProv)
        CryptReleaseContext(phProv, 0);

    return retValue;

}
```

- flag：`DASCT{H@sh_a^d_Aes_6y_WinCrypt}`

