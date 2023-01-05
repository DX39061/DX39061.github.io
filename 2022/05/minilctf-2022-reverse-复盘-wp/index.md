# miniLCTF 2022 Reverse 复盘 & wp


## not RC4

- RISC-V 逆向，有找到ida的插件，但装上一直报错，放弃

- 又找到`Ghidra`，反编译很丑但能用，使劲看发现是个vm

- 大致流程及指令

```c
0
0xf1                6
LAB_00100b7e        8

{
  int i;

  for (i = 0; i < 4; i ++) {
    if (&enc_flag[i]) != check_array[i]) {      //longlong
      printf("Wrong!");
      exit(0);
    }
  }
  op_pointer++;
  return;
}




0xf2                10
LAB_00100bfe        12

{
  if (key_num_2 < opcode[op_pointer + 2]) {//0x0b
    op_pointer -= opcode[op_pointer + 1];//4
    key_num_2 ++;
  }
  else {
    key_num_2 = 0;
    op_pointer += 3;
  }
  return;
}




0xf3                14
LAB_00100974        16

key_const_1 = 0x0000000064627421;
key_const_2 = 0x0000000079796473;
{
  left_8_bytes = input_left_8_bytes +  key_const_1;
  right_8_bytes = input_right_8_bytes + key_const_2;
  op_pointer += 2;
  return;
}




0xf4                18
LAB_00100a10        20

{
  if (opcode[op_pointer + 1] == 0xe1) {
    left_8_bytes = key_const_1 + ((right_8_bytes ^ left_8_bytes) >> (-right_8_bytes & 0x3f) | (right_8_bytes ^ left_8_bytes) << (right_8_bytes & 0x3fU));
    left_8_bytes = key_const_1 + rol(right_8_bytes ^ left_8_bytes, 6);
  }
  if (opcode[*op_pointer + 1] == 0xe2) {
    right_8_bytes = key_const_2 + ((right_8_bytes ^ left_8_bytes) >> (-left_8_bytes & 0x3f) | (right_8_bytes ^ left_8_bytes) << (left_8_bytes & 0x3f));
  }
  op_pointer += 2;
  return;
}

void RC5_ENCRYPT(WORD *pt, WORD *ct)
{
   WORD i, A = pt[0] + S[0], B = pt[1] + S[1];

   for(i = 1; i <= r; i++)
   {
      A = ROTL(A ^ B, B) + S[2*i];
      B = ROTL(B ^ A, A) + S[2*i + 1];
   }
   ct[0] = A; ct[1] = B;
}



(val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


0xf5                22
LAB_00100af0        24

{
  *(undefined8 *)(&check_array + (longlong)key_num_1 * 8) = left_8_bytes;
  *(undefined8 *)(&check_array + (longlong)(key_num_1 + 1) * 8) = right_8_bytes;
  left_8_bytes = 0;
  right_8_bytes = 0;
  key_num_1 += 2;
  op_pointer++;
  return;
}


opcode = { 0xf3, 0x00, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5,       0xf3, 0x02, 0xf4, 0xe1, 0xf4, 0xe2, 0xf2, 0x04, 0x0b, 0xf5, 0xf1, 0xff }


enc_flag = { 0xca, 0x82, 0xef, 0x95, 0xbb, 0x1d, 0xc2, 0x4b, 0xbe, 0x47, 0xb5, 0x71, 0xae, 0xec, 0x7b, 0xf5, 0xcd, 0xf6, 0xe7, 0x15, 0xab, 0xbd, 0xa1, 0x80, 0x85, 0x63, 0x77, 0xe1, 0xd7, 0x93, 0xc7, 0xa3 }
```

- 最后得知整个流程是个去掉了初始化的`RC5`（not RC4就在这

- exp

```python
from Crypto.Util.number import *
enc_flag = [0x4bc21dbb95ef82ca, 0xf57becae71b547be, 0x80a1bdab15e7f6cd, 0xa3c793d7e1776385]

key_const_1 = 0x0000000064627421
key_const_2 = 0x0000000079796473

rol = lambda val, r_bts, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

left_8_bytes = 0x4bc21dbb95ef82ca
right_8_bytes = 0xf57becae71b547be

for j in range(12):

    right_8_bytes = ror((right_8_bytes - key_const_2), left_8_bytes, 64) ^ left_8_bytes
    left_8_bytes = ror((left_8_bytes - key_const_1), right_8_bytes,64) ^ right_8_bytes

left_8_bytes -= key_const_1
right_8_bytes -= key_const_2

print(long_to_bytes(left_8_bytes), long_to_bytes(right_8_bytes))
```

- 字节序问题，最后要逆过来看

- flag`miniLCTF{I_hate_U_r1sc-V!}`

## lemon

- lemon语言逆向，给了一段字节码

- 吐槽一下官方仓库readme写得太简略了，费了好大劲才搞懂工具怎么用

- 然后就是体力活了

- 猜一下，写点代码，`\dis`一下，和题目文件比对一下，还原源代码

```python
var v0 = 221492336;

def next(){
            v0 = (v0*3735928559 + 2974593325) % 4294967295;
            return v0;
        }

class RunMe(){
        def __init__(var n){
            self.enc = [];
            self.flag = [];
            self.res  = [2141786733, 76267819, 37219027, 219942343, 755999918, 701306806, 532732060, 334234642, 524809386, 333469062, 160092960, 126810196, 238089888, 301365991, 258515107, 424705310, 1041878913, 618187854, 4680810, 827308967, 66957703, 924471115, 735310319, 541128627, 47689903, 459905620, 495518230, 167708778, 586337393, 521761774, 861166604, 626644061, 1030425184, 665229750, 330150339];
            for (var v1=0; v1<n; v1+=1){
                    self.enc.append(next());
            }
        }

        def sign(var x, var y){
            for(var v2=0; v2<35; v2+=1){
                self.flag.append(x[v2] ^ y[v2]);
            }
        }
    }
    print("Starting");
    var v5 = RunMe(35);
    v5.sign(v5.res, v5.enc);
    print(v5.flag);
    print("Done");
```

- 运行得flag

- flag`miniLctf{l3m0n_1s_s0_s0urrR77RrrR7}`

## whatAssembly

- 在js里藏着一个`flag.wasm`，直接请求下载就行

- 下载官方工具包`wabt`

- 使用`wasm2c`工具将wasm文件反编译成`flag.c`文件，`./wasm2c wasm.wasm -o wasm.c`，但是可读性不高

- 继续优化，把`wasm-rt.h`和`wasm.h`和`flag.c`放在同一目录下，`gcc -c flag.c -o flag`，进行只编译不链接，这一步可能会出奇怪的问题，目前原因不明

- 成功后就可拖进ida进行静态分析，会好看很多

- 前面还尝试了jeb4.0（支持wasm直接反汇编/反编译），可用，但巨丑，效果远不如ida，故放弃

- 以下结合[出题人放出的源码](https://github.com/XDSEC/miniLCTF_2022/blob/main/Official/MiniLCTF2022%20WhatAssembly%20%26%20Lemon%20Official%20Writeup.md)分析，附带详细注释

- check函数

```c
__int64 __fastcall w2c_check(unsigned int flag, unsigned int key, unsigned int enc)
{
  int v3; // eax
  unsigned int check_sp; // [rsp+24h] [rbp-47Ch]
  unsigned int v7; // [rsp+40h] [rbp-460h]
  unsigned int v8; // [rsp+44h] [rbp-45Ch]
  unsigned int v9; // [rsp+48h] [rbp-458h]
  unsigned int v10; // [rsp+4Ch] [rbp-454h]
  unsigned int v11; // [rsp+50h] [rbp-450h]
  unsigned int v12; // [rsp+54h] [rbp-44Ch]
  signed int v13; // [rsp+90h] [rbp-410h]
  int v14; // [rsp+B4h] [rbp-3ECh]
  unsigned int flag_cpy_len; // [rsp+DCh] [rbp-3C4h]
  unsigned int v16; // [rsp+E0h] [rbp-3C0h]
  unsigned int flag_cpy_addr; // [rsp+E4h] [rbp-3BCh]
  unsigned int v18; // [rsp+E8h] [rbp-3B8h]
  unsigned int v19; // [rsp+ECh] [rbp-3B4h]
  unsigned int v20; // [rsp+F4h] [rbp-3ACh]
  unsigned int v21; // [rsp+F8h] [rbp-3A8h]
  int key_addr; // [rsp+120h] [rbp-380h]
  unsigned int v23; // [rsp+128h] [rbp-378h]
  unsigned int v24; // [rsp+12Ch] [rbp-374h]
  unsigned int v25; // [rsp+140h] [rbp-360h]
  int i; // [rsp+160h] [rbp-340h]
  int v27; // [rsp+194h] [rbp-30Ch]
  int v28; // [rsp+198h] [rbp-308h]
  int v29; // [rsp+1A0h] [rbp-300h]
  unsigned int v30; // [rsp+1A8h] [rbp-2F8h]
  int v31; // [rsp+1B4h] [rbp-2ECh]
  int v32; // [rsp+300h] [rbp-1A0h]
  int v33; // [rsp+30Ch] [rbp-194h]
  int v34; // [rsp+324h] [rbp-17Ch]
  char v35; // [rsp+32Ch] [rbp-174h]
  unsigned int v36; // [rsp+34Ch] [rbp-154h]
  char v37; // [rsp+374h] [rbp-12Ch]
  unsigned int v38; // [rsp+39Ch] [rbp-104h]
  int v39; // [rsp+3A0h] [rbp-100h]
  int v40; // [rsp+3ACh] [rbp-F4h]
  int v41; // [rsp+3BCh] [rbp-E4h]
  char v42; // [rsp+3CCh] [rbp-D4h]
  unsigned int v43; // [rsp+3ECh] [rbp-B4h]
  char v44; // [rsp+414h] [rbp-8Ch]
  unsigned int v45; // [rsp+43Ch] [rbp-64h]
  unsigned int v46; // [rsp+458h] [rbp-48h]
  unsigned int v47; // [rsp+460h] [rbp-40h]
  int v48; // [rsp+46Ch] [rbp-34h]
  unsigned int v49; // [rsp+470h] [rbp-30h]
  unsigned int v50; // [rsp+470h] [rbp-30h]
  unsigned int v51; // [rsp+470h] [rbp-30h]
  unsigned int v52; // [rsp+470h] [rbp-30h]
  unsigned int v53; // [rsp+470h] [rbp-30h]
  unsigned int v54; // [rsp+470h] [rbp-30h]
  unsigned int v55; // [rsp+474h] [rbp-2Ch]
  __int64 v56; // [rsp+480h] [rbp-20h]
  __int64 v57; // [rsp+498h] [rbp-8h]

  w2c___stack_pointer -= 112;                   // new vm stack frame
  check_sp = w2c___stack_pointer;
  i32_store(&w2c_memory, (unsigned int)w2c___stack_pointer + 104LL, flag);// push flag
  i32_store(&w2c_memory, check_sp + 100LL, key);// push key
  i32_store(&w2c_memory, check_sp + 96LL, enc); // push enc
  v56 = i64_load(&w2c_memory, 1032LL);
  i64_store(&w2c_memory, check_sp + 88, v56);   // table
  v57 = i64_load(&w2c_memory, 1024LL);
  i64_store(&w2c_memory, check_sp + 80, v57);   // another table
  v7 = i32_load(&w2c_memory, check_sp + 104LL); // push len(flag)
  v8 = w2c_strlen(v7);
  i32_store(&w2c_memory, check_sp + 76LL, v8);
  v9 = i32_load(&w2c_memory, check_sp + 100LL); // push len(key)
  v10 = w2c_strlen(v9);
  i32_store(&w2c_memory, check_sp + 72LL, v10);
  v11 = i32_load(&w2c_memory, check_sp + 96LL); // push len(enc)
  v12 = w2c_strlen(v11);
  i32_store(&w2c_memory, check_sp + 68LL, v12);
  if ( (int)i32_load(&w2c_memory, check_sp + 72LL) >= 8// len(key) >= 8
    && (v13 = 4 * i32_load(&w2c_memory, check_sp + 76LL), v13 > (int)(i32_load(&w2c_memory, check_sp + 68LL) - 32))// 4 * len(flag) > len(enc) - 32
    && (v14 = 4 * i32_load(&w2c_memory, check_sp + 76LL), v14 <= (int)i32_load(&w2c_memory, check_sp + 68LL)) )// 4 * len(flag) <= len(enc)
  {
    flag_cpy_len = (i32_load(&w2c_memory, check_sp + 76LL) + 15) & 0xFFFFFFF0;// flag_cpy_len = (flag_len + 15) & ~15
    i32_store(&w2c_memory, check_sp + 64LL, flag_cpy_len);
    v16 = i32_load(&w2c_memory, check_sp + 64LL);
    flag_cpy_addr = w2c_dlmalloc(v16);          // malloc(flag_cpy_len)
    i32_store(&w2c_memory, check_sp + 60LL, flag_cpy_addr);
    v18 = i32_load(&w2c_memory, check_sp + 60LL);
    v19 = i32_load(&w2c_memory, check_sp + 64LL);
    w2c_memset(v18, 0LL, v19);                  // memset(flag_cpy_addr, 0, flag_cpy_len)
    v20 = i32_load(&w2c_memory, check_sp + 60LL);
    v21 = i32_load(&w2c_memory, check_sp + 104LL);
    v55 = i32_load(&w2c_memory, check_sp + 76LL);
    w2c___memcpy(v20, v21, v55);                // memcpy(flag_cpy_addr, flag, flag_len)
    i32_store(&w2c_memory, check_sp + 28LL, 0LL);// i = 0
    while ( (int)i32_load(&w2c_memory, check_sp + 28LL) < 8 )// while(i < 8)
    {
      key_addr = i32_load(&w2c_memory, check_sp + 100LL);
      v23 = i32_load(&w2c_memory, check_sp + 28LL) + key_addr;// key[i]
      v24 = i32_load8_u(&w2c_memory, v23);
      v25 = i32_load(&w2c_memory, check_sp + 28LL) + check_sp + 32;// new s
      i32_store8(&w2c_memory, v25, v24);        // s[i] = key[i]
      v49 = i32_load(&w2c_memory, check_sp + 28LL) + 1;// i++
      i32_store(&w2c_memory, check_sp + 28LL, v49);
    }
    i32_store(&w2c_memory, check_sp + 24LL, 0LL);// is_correct
    i32_store(&w2c_memory, check_sp + 20LL, 0LL);// i = 0
    while ( 1 )
    {
      i = i32_load(&w2c_memory, check_sp + 20LL);
      if ( i >= (int)i32_load(&w2c_memory, check_sp + 76LL) )// if(i >= flag_len)
        break;
      i32_store(&w2c_memory, check_sp + 16LL, 0LL);// j = 0
      while ( (int)i32_load(&w2c_memory, check_sp + 16LL) < 8 )// while(j < 8)
      {
        v27 = i32_load(&w2c_memory, check_sp + 60LL);// flag_cpy_addr
        v28 = i32_load(&w2c_memory, check_sp + 20LL);// i
        v29 = i32_load(&w2c_memory, check_sp + 16LL) + v28;// j + i
        v30 = i32_load8_u(&w2c_memory, (unsigned int)(v29 + v27));// flag_cpy[i+j]
        v31 = i32_load(&w2c_memory, check_sp + 16LL) + 8;// j + 8
        i32_store8(&w2c_memory, v31 + check_sp + 32, v30);// s[j+8] = flag_cpy[i+j]
        v50 = i32_load(&w2c_memory, check_sp + 16LL) + 1;// j++
        i32_store(&w2c_memory, check_sp + 16LL, v50);
      }
      i32_store(&w2c_memory, check_sp + 12LL, 0LL);// j = 0
      while ( (int)i32_load(&w2c_memory, check_sp + 12LL) < 42 )// while(j < 42)
      {
        w2c_qua_rou(check_sp + 32, 12LL, 8LL, 4LL, 0LL);
        w2c_qua_rou(check_sp + 32, 13LL, 9LL, 5LL, 1LL);
        w2c_qua_rou(check_sp + 32, 14LL, 10LL, 6LL, 2LL);
        w2c_qua_rou(check_sp + 32, 15LL, 11LL, 7LL, 3LL);
        w2c_qua_rou(check_sp + 32, 15LL, 10LL, 5LL, 0LL);
        w2c_qua_rou(check_sp + 32, 12LL, 11LL, 6LL, 1LL);
        w2c_qua_rou(check_sp + 32, 13LL, 8LL, 7LL, 2LL);
        w2c_qua_rou(check_sp + 32, 14LL, 9LL, 4LL, 3LL);
        v51 = i32_load(&w2c_memory, check_sp + 12LL) + 1;// j++
        i32_store(&w2c_memory, check_sp + 12LL, v51);
      }
      i32_store(&w2c_memory, check_sp + 8LL, 0LL);// j = 0
      while ( (int)i32_load(&w2c_memory, check_sp + 8LL) < 16 )// while(j < 16)
      {
        v32 = i32_load(&w2c_memory, check_sp + 96LL);// enc
        v33 = 4 * i32_load(&w2c_memory, check_sp + 20LL);// 4 * i
        v34 = 2 * i32_load(&w2c_memory, check_sp + 8LL) + v33;// 2*j + 4*i
        v35 = i32_load8_u(&w2c_memory, (unsigned int)(v34 + v32));// enc[2*j + 4*i]
        v36 = i32_load(&w2c_memory, check_sp + 8LL) + check_sp + 32;// s[j]
        v48 = (unsigned __int8)i32_load8_u(&w2c_memory, v36);
        v37 = i32_load8_u(&w2c_memory, v48 / 16 + check_sp + 80);// table[s[j] / 16]
        v38 = (v35 != v37) | (unsigned int)i32_load(&w2c_memory, check_sp + 24LL);// is_correct |= (enc[2*j + 4*i] != table[s[j] / 16])
        i32_store(&w2c_memory, check_sp + 24LL, v38);
        v39 = i32_load(&w2c_memory, check_sp + 96LL);
        v40 = 4 * i32_load(&w2c_memory, check_sp + 20LL);
        v41 = 2 * i32_load(&w2c_memory, check_sp + 8LL) + v40;
        v42 = i32_load8_u(&w2c_memory, (unsigned int)(v41 + 1 + v39));
        v43 = i32_load(&w2c_memory, check_sp + 8LL) + check_sp + 32;
        v3 = (unsigned __int8)i32_load8_u(&w2c_memory, v43) % 16;
        v44 = i32_load8_u(&w2c_memory, v3 + check_sp + 80);
        v45 = (v42 != v44) | (unsigned int)i32_load(&w2c_memory, check_sp + 24LL);// is_correct |= (enc[2*j + 4*i + 1] != table[s[j] % 16])
        i32_store(&w2c_memory, check_sp + 24LL, v45);
        v52 = i32_load(&w2c_memory, check_sp + 8LL) + 1;// j++
        i32_store(&w2c_memory, check_sp + 8LL, v52);
      }
      v53 = i32_load(&w2c_memory, check_sp + 20LL) + 8;// i += 8
      i32_store(&w2c_memory, check_sp + 20LL, v53);
    }
    v46 = i32_load(&w2c_memory, check_sp + 60LL);// free(flag_cpy_addr)
    w2c_dlfree(v46);
    v54 = i32_load(&w2c_memory, check_sp + 24LL);// is_correct
    i32_store(&w2c_memory, check_sp + 108LL, v54);
  }
  else
  {
    i32_store(&w2c_memory, check_sp + 108LL, 0xFFFFFFFFLL);
  }
  v47 = i32_load(&w2c_memory, check_sp + 108LL);
  w2c___stack_pointer = check_sp + 112;         // destory vm stack frame
  return v47;
}
```

- 其中的table是在之前的`init_memory`中被初始化的

```c
void *init_memory()
{
  wasm_rt_allocate_memory(&w2c_memory, 256LL, 256LL);
  if ( (unsigned int)dword_14DE0 <= 0xD2B )
    wasm_rt_trap(1LL);
  ZNSt16allocator_traitsISaINSt8__detail10_Hash_nodeISt4pairIKN6spdlog5level10level_enumEN3fmt2v617basic_string_viewIcEEELb0EEEEE10deallocateERSD_PSC_m(
    (void *)(w2c_memory + 1024),
    "0123456789abcdefunsigned short",
    0x92CuLL);
  if ( (unsigned int)dword_14DE0 <= 0xD2F )
    wasm_rt_trap(1LL);
  ZNSt16allocator_traitsISaINSt8__detail10_Hash_nodeISt4pairIKN6spdlog5level10level_enumEN3fmt2v617basic_string_viewIcEEELb0EEEEE10deallocateERSD_PSC_m(
    (void *)(w2c_memory + 3372),
    &data_segment_data_1,
    4uLL);
  if ( (unsigned int)dword_14DE0 <= 0xD2F )
    wasm_rt_trap(1LL);
  return ZNSt16allocator_traitsISaINSt8__detail10_Hash_nodeISt4pairIKN6spdlog5level10level_enumEN3fmt2v617basic_string_viewIcEEELb0EEEEE10deallocateERSD_PSC_m(
           (void *)(w2c_memory + 3376),
           (const void *)data_segment_data_2,
           0LL);
}
```

- `w2c_qua_rou`函数

```c
__int64 __fastcall w2c_qua_rou(unsigned int a1, unsigned int a, unsigned int b, unsigned int c, unsigned int d)
{
  unsigned int v9; // [rsp+34h] [rbp-2ACh]
  int v10; // [rsp+38h] [rbp-2A8h]
  unsigned int v11; // [rsp+40h] [rbp-2A0h]
  char v12; // [rsp+4Ch] [rbp-294h]
  int v13; // [rsp+50h] [rbp-290h]
  unsigned int v14; // [rsp+58h] [rbp-288h]
  char v15; // [rsp+5Ch] [rbp-284h]
  int v16; // [rsp+7Ch] [rbp-264h]
  unsigned int v17; // [rsp+84h] [rbp-25Ch]
  char v18; // [rsp+90h] [rbp-250h]
  int v19; // [rsp+94h] [rbp-24Ch]
  unsigned int v20; // [rsp+9Ch] [rbp-244h]
  char v21; // [rsp+A0h] [rbp-240h]
  int v22; // [rsp+C4h] [rbp-21Ch]
  unsigned int v23; // [rsp+CCh] [rbp-214h]
  unsigned int v24; // [rsp+DCh] [rbp-204h]
  int v25; // [rsp+E0h] [rbp-200h]
  unsigned int v26; // [rsp+E8h] [rbp-1F8h]
  char v27; // [rsp+F4h] [rbp-1ECh]
  int v28; // [rsp+F8h] [rbp-1E8h]
  unsigned int v29; // [rsp+100h] [rbp-1E0h]
  char v30; // [rsp+104h] [rbp-1DCh]
  int v31; // [rsp+124h] [rbp-1BCh]
  unsigned int v32; // [rsp+12Ch] [rbp-1B4h]
  char v33; // [rsp+138h] [rbp-1A8h]
  int v34; // [rsp+13Ch] [rbp-1A4h]
  unsigned int v35; // [rsp+144h] [rbp-19Ch]
  char v36; // [rsp+148h] [rbp-198h]
  int v37; // [rsp+16Ch] [rbp-174h]
  unsigned int v38; // [rsp+174h] [rbp-16Ch]
  unsigned int v39; // [rsp+184h] [rbp-15Ch]
  int v40; // [rsp+188h] [rbp-158h]
  unsigned int v41; // [rsp+190h] [rbp-150h]
  char v42; // [rsp+19Ch] [rbp-144h]
  int v43; // [rsp+1A0h] [rbp-140h]
  unsigned int v44; // [rsp+1A8h] [rbp-138h]
  char v45; // [rsp+1ACh] [rbp-134h]
  int v46; // [rsp+1CCh] [rbp-114h]
  unsigned int v47; // [rsp+1D4h] [rbp-10Ch]
  char v48; // [rsp+1E0h] [rbp-100h]
  int v49; // [rsp+1E4h] [rbp-FCh]
  unsigned int v50; // [rsp+1ECh] [rbp-F4h]
  char v51; // [rsp+1F0h] [rbp-F0h]
  int v52; // [rsp+214h] [rbp-CCh]
  unsigned int v53; // [rsp+21Ch] [rbp-C4h]
  unsigned int v54; // [rsp+22Ch] [rbp-B4h]
  int v55; // [rsp+230h] [rbp-B0h]
  unsigned int v56; // [rsp+238h] [rbp-A8h]
  char v57; // [rsp+244h] [rbp-9Ch]
  int v58; // [rsp+248h] [rbp-98h]
  unsigned int v59; // [rsp+250h] [rbp-90h]
  char v60; // [rsp+254h] [rbp-8Ch]
  int v61; // [rsp+274h] [rbp-6Ch]
  unsigned int v62; // [rsp+27Ch] [rbp-64h]
  char v63; // [rsp+288h] [rbp-58h]
  int v64; // [rsp+28Ch] [rbp-54h]
  unsigned int v65; // [rsp+294h] [rbp-4Ch]
  char v66; // [rsp+298h] [rbp-48h]
  int v67; // [rsp+2BCh] [rbp-24h]
  unsigned int v68; // [rsp+2C4h] [rbp-1Ch]
  unsigned int v69; // [rsp+2D4h] [rbp-Ch]

  v9 = w2c___stack_pointer - 32;
  i32_store(&w2c_memory, (unsigned int)(w2c___stack_pointer - 32) + 28LL, a1);
  i32_store(&w2c_memory, v9 + 24LL, a);
  i32_store(&w2c_memory, v9 + 20LL, b);
  i32_store(&w2c_memory, v9 + 16LL, c);
  i32_store(&w2c_memory, v9 + 12LL, d);
  v10 = i32_load(&w2c_memory, v9 + 28LL);
  v11 = i32_load(&w2c_memory, v9 + 24LL) + v10; // s[a]
  v12 = i32_load8_u(&w2c_memory, v11);
  v13 = i32_load(&w2c_memory, v9 + 28LL);
  v14 = i32_load(&w2c_memory, v9 + 12LL) + v13; // s[d]
  v15 = i32_load8_u(&w2c_memory, v14);
  v16 = i32_load(&w2c_memory, v9 + 28LL);
  v17 = i32_load(&w2c_memory, v9 + 24LL) + v16; // s[a]
  v18 = i32_load8_u(&w2c_memory, v17);
  v19 = i32_load(&w2c_memory, v9 + 28LL);
  v20 = i32_load(&w2c_memory, v9 + 12LL) + v19; // s[d]
  v21 = i32_load8_u(&w2c_memory, v20);
  v22 = i32_load(&w2c_memory, v9 + 28LL);
  v23 = i32_load(&w2c_memory, v9 + 20LL) + v22; // s[b]
  v24 = (((int)(unsigned __int8)(v21 + v18) >> 4) | (16 * (unsigned __int8)(v15 + v12))) ^ (unsigned __int8)i32_load8_u(&w2c_memory, v23);
  i32_store8(&w2c_memory, v23, v24);            // s[b] ^= ((s[a] + s[d]) >> 4) | ((s[a] + s[d]) << 4)
  v25 = i32_load(&w2c_memory, v9 + 28LL);
  v26 = i32_load(&w2c_memory, v9 + 16LL) + v25; // s[c]
  v27 = i32_load8_u(&w2c_memory, v26);
  v28 = i32_load(&w2c_memory, v9 + 28LL);
  v29 = i32_load(&w2c_memory, v9 + 20LL) + v28; // s[b]
  v30 = i32_load8_u(&w2c_memory, v29);
  v31 = i32_load(&w2c_memory, v9 + 28LL);
  v32 = i32_load(&w2c_memory, v9 + 16LL) + v31; // s[c]
  v33 = i32_load8_u(&w2c_memory, v32);
  v34 = i32_load(&w2c_memory, v9 + 28LL);
  v35 = i32_load(&w2c_memory, v9 + 20LL) + v34; // s[b]
  v36 = i32_load8_u(&w2c_memory, v35);
  v37 = i32_load(&w2c_memory, v9 + 28LL);
  v38 = i32_load(&w2c_memory, v9 + 12LL) + v37; // s[d]
  v39 = (((int)(unsigned __int8)(v36 + v33) >> 6) | (4 * (unsigned __int8)(v30 + v27))) ^ (unsigned __int8)i32_load8_u(&w2c_memory, v38);
  i32_store8(&w2c_memory, v38, v39);            // s[d] ^= ((s[b] + s[c]) >> 6) | ((s[c] + s[b]) << 2)
  v40 = i32_load(&w2c_memory, v9 + 28LL);
  v41 = i32_load(&w2c_memory, v9 + 20LL) + v40; // s[b]
  v42 = i32_load8_u(&w2c_memory, v41);
  v43 = i32_load(&w2c_memory, v9 + 28LL);
  v44 = i32_load(&w2c_memory, v9 + 24LL) + v43; // s[a]
  v45 = i32_load8_u(&w2c_memory, v44);
  v46 = i32_load(&w2c_memory, v9 + 28LL);
  v47 = i32_load(&w2c_memory, v9 + 20LL) + v46; // s[b]
  v48 = i32_load8_u(&w2c_memory, v47);
  v49 = i32_load(&w2c_memory, v9 + 28LL);
  v50 = i32_load(&w2c_memory, v9 + 24LL) + v49; // s[a]
  v51 = i32_load8_u(&w2c_memory, v50);
  v52 = i32_load(&w2c_memory, v9 + 28LL);
  v53 = i32_load(&w2c_memory, v9 + 16LL) + v52; // s[c]
  v54 = (((int)(unsigned __int8)(v51 + v48) >> 5) | (8 * (unsigned __int8)(v45 + v42))) ^ (unsigned __int8)i32_load8_u(&w2c_memory, v53);
  i32_store8(&w2c_memory, v53, v54);            // s[c] ^= ((s[b] + s[a]) >> 5) | ((s[b] + s[a]) << 3)
  v55 = i32_load(&w2c_memory, v9 + 28LL);
  v56 = i32_load(&w2c_memory, v9 + 12LL) + v55; // s[d]
  v57 = i32_load8_u(&w2c_memory, v56);
  v58 = i32_load(&w2c_memory, v9 + 28LL);
  v59 = i32_load(&w2c_memory, v9 + 16LL) + v58; // s[c]
  v60 = i32_load8_u(&w2c_memory, v59);
  v61 = i32_load(&w2c_memory, v9 + 28LL);
  v62 = i32_load(&w2c_memory, v9 + 12LL) + v61; // s[d]
  v63 = i32_load8_u(&w2c_memory, v62);
  v64 = i32_load(&w2c_memory, v9 + 28LL);
  v65 = i32_load(&w2c_memory, v9 + 16LL) + v64; // s[c]
  v66 = i32_load8_u(&w2c_memory, v65);
  v67 = i32_load(&w2c_memory, v9 + 28LL);
  v68 = i32_load(&w2c_memory, v9 + 24LL) + v67; // s[a]
  v69 = (((int)(unsigned __int8)(v66 + v63) >> 7) | (2 * (unsigned __int8)(v60 + v57))) ^ (unsigned __int8)i32_load8_u(&w2c_memory, v68);
  return i32_store8(&w2c_memory, v68, v69);     // s[a] ^= ((s[d] + s[c]) >> 7) | ((s[d] + s[c]) << 1)
}
```

- 复原原函数

```c
int check(char *flag, char *key, char *enc){
    char table[] = "0123456789abcdef";
    char s[1000];
    int flag_len = strlen(flag);
    int key_len = strlen(key);
    int enc_len = strlen(enc);
    int is_correct = 0;

    if(key_len >= 8 && 4 * flag_len > enc_len && 4 * flag_len <= enc_len){
        int flag_cpy_len = (flag_len + 15) & ~15;
        char *flag_cpy_addr = malloc(flag_cpy_len);
        memset(flag_cpy_addr, 0, flag_cpy_len);
        memcpy(flag_cpy_addr, flag, flag_len);
        for(int i = 0; i < 8; i++){
            s[i] = key[i];
        }
        for(int i = 0; i < enc_len; i += 8){
            for(int j = 0; j < 8; j++){
                s[j + 8] = flag_cpy_addr[i + j];
            }
            for(int j = 0; j < 42; j++){
                qua_rou(s, 12LL, 8LL, 4LL, 0LL);
                qua_rou(s, 13LL, 9LL, 5LL, 1LL);
                qua_rou(s, 14LL, 10LL, 6LL, 2LL);
                qua_rou(s, 15LL, 11LL, 7LL, 3LL);
                qua_rou(s, 15LL, 10LL, 5LL, 0LL);
                qua_rou(s, 12LL, 11LL, 6LL, 1LL);
                qua_rou(s, 13LL, 8LL, 7LL, 2LL);
                qua_rou(s, 14LL, 9LL, 4LL, 3LL);
            }

            for(int j = 0; j < 16; j++){
                is_correct |= (enc[2*j + 4*i] != table[s[j] / 16]);
                is_correct |= (enc[2*j + 4*i + 1] != table[s[j] % 16]);
            }
        }
    }
    return is_correct;
}
```

- 逆它，重在理解每一步是在干啥，不用每一句都死逆

- 如flag_cpy的复制可省略，key并无用处，最下面的for循环中`/16`和`%16`是分别对一个字节的低8位和高8位运算

- 脚本

```c
#include<stdio.h>

char enc[] = "05779c24d9249e693fa7ac4a10c68dfbd3520083b33f56e90fd84978b6a15c970b976779a8fefe91fb87d2221c9a1f87ed7eaddb8ae6370f9de69e3a7a5c5c488cde79756b0b9f1713e749edd41cff04";
char table[] = "0123456789abcdef";
char key[]="D33.B4T0";
char flag[1000];
unsigned char s[1000];

int index(char c){
    for(int i = 0; i < 16; i++){
        if(table[i] == c) return i;
    }
    return -1;
}

void qua_rou_rev(char *s, int a, int b, int c, int d){
    s[a] ^= ((((s[d] + s[c]) & 0xff) >> 7) | (((s[d] + s[c]) & 0xff) << 1)) & 0xff;
    s[c] ^= ((((s[b] + s[a]) & 0xff) >> 5) | (((s[b] + s[a]) & 0xff) << 3)) & 0xff;
    s[d] ^= ((((s[b] + s[c]) & 0xff) >> 6) | (((s[c] + s[b]) & 0xff) << 2)) & 0xff;
    s[b] ^= ((((s[a] + s[d]) & 0xff) >> 4) | (((s[a] + s[d]) & 0xff) << 4)) & 0xff;
}

int main(){
    //0 8 16 24 32
    for(int i = 0; i < 40; i += 8){
        for(int j = 0; j < 16; j++){
            s[j] = index(enc[2*j + 4*i]) * 16 + index(enc[2*j + 4*i + 1]);//分别取s[i]一个字节的低8未和高8位
        }
        for(int j = 0; j < 42; j++){
            qua_rou_rev(s, 14, 9, 4, 3);
            qua_rou_rev(s, 13, 8, 7, 2);
            qua_rou_rev(s, 12, 11, 6, 1);
            qua_rou_rev(s, 15, 10, 5, 0);
            qua_rou_rev(s, 15, 11, 7, 3);
            qua_rou_rev(s, 14, 10, 6, 2);
            qua_rou_rev(s, 13, 9, 5, 1);
            qua_rou_rev(s, 12, 8, 4, 0);
        }

        for(int j = 0; j < 16; j++){
            flag[i+j] = s[j+8];
        }
    }
    for(int i = 0; i < 40; i++){
        printf("%c", flag[i]);
    }
}
```

- `miniLctf{0ooo00oh!h3ll0_WASM_h4ck3r!}`

## twin

- ref:[P.Z.师傅的wp](https://ppppz.net/2022/05/18/miniLCTF2022-TWIN/)

- > 创建或终止线程时，TLS回调函数都会自动调用执行

- 在ida里找到`TlsCallback_0`，打开是空的，原因是里面有个反调试

- 有一句`call $+5`实际是原地tp，后一句计算正确的地址，然后retn实现跳转，直接把它从这句一直到`retn`全都nop掉即可，后面还有很多处同理

- 修复后的`TlsCallback_0`函数

```c
void __cdecl TlsCallback_0(int a1, int a2)
{
  char *v2; // eax
  char Buffer[80]; // [esp+10h] [ebp-11Ch] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+60h] [ebp-CCh] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+A4h] [ebp-88h] BYREF
  char v7[22]; // [esp+B8h] [ebp-74h] BYREF
  char v8[4]; // [esp+CEh] [ebp-5Eh] BYREF
  char v9[44]; // [esp+D4h] [ebp-58h] BYREF
  char v10[12]; // [esp+100h] [ebp-2Ch] BYREF
  CHAR Name[8]; // [esp+10Ch] [ebp-20h] BYREF
  CHAR ApplicationName[8]; // [esp+114h] [ebp-18h] BYREF
  char v13[8]; // [esp+11Ch] [ebp-10h] BYREF
  char Format[7]; // [esp+124h] [ebp-8h] BYREF
  uint8_t v15; // [esp+12Bh] [ebp-1h]

  if ( a2 == 1 )
  {
    memset(Buffer, 0, sizeof(Buffer));
    sub_401930(Buffer);
    v15 = 0;
    v15 = NtCurrentPeb()->BeingDebugged;
    if ( !v15 )
      *(&TlsCallbacks + 1) = (int (__cdecl *)(int, int))sub_401D60;
    strcpy(Name, "93>8");
    sub_4018C0(Name);
    hObject = CreateFileMappingA(0, 0, 4u, 0, 0x1000u, Name);
    *(_DWORD *)dword_404448 = MapViewOfFile(hObject, 0xF001Fu, 0, 0, 0x1000u);
    v7[0] = 47;
    v7[1] = 19;
    v7[2] = 26;
    v7[3] = 30;
    v7[4] = 12;
    v7[5] = 26;
    v7[6] = 95;
    v7[7] = 22;
    v7[8] = 17;
    v7[9] = 15;
    v7[10] = 10;
    v7[11] = 11;
    v7[12] = 95;
    v7[13] = 6;
    v7[14] = 16;
    v7[15] = 10;
    v7[16] = 13;
    v7[17] = 95;
    v7[18] = 25;
    v7[19] = 19;
    v7[20] = 30;
    v7[21] = 24;
    strcpy(v8, "E_");
    v2 = (char *)sub_4018C0(v7);
    sub_401930(v2);
    Format[0] = 90;
    Format[1] = 12;
    Format[2] = 0;
    sub_4018C0(Format);
    sub_401130(Format, dword_404448[0]);
  }
  if ( !a2 )
  {
    ApplicationName[0] = 81;
    ApplicationName[1] = 80;
    ApplicationName[2] = 11;
    ApplicationName[3] = 18;
    ApplicationName[4] = 15;
    ApplicationName[5] = 0;
    sub_4018C0(ApplicationName);
    sub_401410();
    memset(&StartupInfo, 0, sizeof(StartupInfo));
    StartupInfo.cb = 68;
    CreateProcessA(ApplicationName, 0, 0, 0, 0, 3u, 0, 0, &StartupInfo, &ProcessInformation);
    v10[0] = 28;
    v10[1] = 16;
    v10[2] = 13;
    v10[3] = 13;
    v10[4] = 26;
    v10[5] = 28;
    v10[6] = 11;
    v10[7] = 117;
    v10[8] = 0;
    v13[0] = 8;
    v13[1] = 13;
    v13[2] = 16;
    v13[3] = 17;
    v13[4] = 24;
    v13[5] = 117;
    v13[6] = 0;
    v9[0] = 47;
    v9[1] = 19;
    v9[2] = 26;
    v9[3] = 30;
    v9[4] = 12;
    v9[5] = 26;
    v9[6] = 95;
    v9[7] = 28;
    v9[8] = 19;
    v9[9] = 16;
    v9[10] = 12;
    v9[11] = 26;
    v9[12] = 95;
    v9[13] = 11;
    v9[14] = 23;
    v9[15] = 26;
    v9[16] = 95;
    v9[17] = 27;
    v9[18] = 26;
    v9[19] = 29;
    v9[20] = 10;
    v9[21] = 24;
    v9[22] = 24;
    v9[23] = 26;
    v9[24] = 13;
    v9[25] = 95;
    v9[26] = 30;
    v9[27] = 17;
    v9[28] = 27;
    v9[29] = 95;
    v9[30] = 11;
    v9[31] = 13;
    v9[32] = 6;
    v9[33] = 95;
    v9[34] = 30;
    v9[35] = 24;
    v9[36] = 30;
    v9[37] = 22;
    v9[38] = 17;
    v9[39] = 117;
    v9[40] = 0;
    sub_401510(ApplicationName, (int)&ProcessInformation);
    if ( dword_404440 == 1 )
    {
      sub_4012C0((_DWORD *)(*(_DWORD *)dword_404448 + 20), 5, (int)&unk_40405C);
      if ( !memcmp((const void *)(*(_DWORD *)dword_404448 + 20), &unk_40402C, 0x14u) )
      {
        sub_4018C0(v10);
        sub_401930(v10);
LABEL_13:
        CloseHandle(hObject);
        return;
      }
    }
    else if ( dword_404440 == -2 )
    {
      sub_4018C0(v9);
      sub_401930(v9);
      goto LABEL_13;
    }
    sub_4018C0(v13);
    sub_401930(v13);
    goto LABEL_13;
  }
}
```

- 其中`a2`存储了`是创建进程还是退出进程`的状态，从而执行不同的代码

- 在程序开始的时候首先进入第一个`if`中的内容

- 注意下面两句

```c
if ( !v15 )
      *(&TlsCallbacks + 1) = (int (__cdecl *)(int, int))sub_401D60;
```

- 把`sub_401D60`放在了`TlsCallbacks`之后，形成了个列表，创建或终止线程时会依次调用这两个函数

- 接下来重点在用创建了新的文件`tmp`

- 动调可得`sub_401130`是`scanf`的功能

- 接着会进入上面在TlsCallbacks之后加上的`sub_401D60`

```c
void __cdecl __noreturn sub_401D60(int a1, int a2)
{
  CHAR ModuleName[16]; // [esp+0h] [ebp-1Ch] BYREF
  CHAR ProcName[12]; // [esp+10h] [ebp-Ch] BYREF

  if ( a2 == 1 )
  {
    ProcName[0] = 40;
    ProcName[1] = 13;
    ProcName[2] = 22;
    ProcName[3] = 11;
    ProcName[4] = 26;
    ProcName[5] = 57;
    ProcName[6] = 22;
    ProcName[7] = 19;
    ProcName[8] = 26;
    ProcName[9] = 0;
    ModuleName[0] = 20;
    ModuleName[1] = 26;
    ModuleName[2] = 13;
    ModuleName[3] = 17;
    ModuleName[4] = 26;
    ModuleName[5] = 19;
    ModuleName[6] = 76;
    ModuleName[7] = 77;
    ModuleName[8] = 81;
    ModuleName[9] = 27;
    ModuleName[10] = 19;
    ModuleName[11] = 19;
    ModuleName[12] = 0;
    sub_4018C0(ProcName);
    sub_4018C0(ModuleName);
    hModule = GetModuleHandleA(ModuleName);
    dword_4043DC = (int)GetProcAddress(hModule, ProcName);
    sub_4016C0(dword_4043DC, sub_401650, hModule);
  }
  ExitProcess(0xFFFFFFFF);
}
```

- `sub_4016C0`实现了对WriteFile函数的hook

```c
int __cdecl sub_4016C0(int a1, int a2, HMODULE a3)
{
  DWORD flOldProtect; // [esp+Ch] [ebp-10h] BYREF
  int v5; // [esp+10h] [ebp-Ch]
  HMODULE v6; // [esp+14h] [ebp-8h]
  LPVOID lpAddress; // [esp+18h] [ebp-4h]

  v6 = GetModuleHandleA(0);
  v5 = (int)v6 + *(_DWORD *)((char *)v6 + *((_DWORD *)v6 + 15) + 128);
  flOldProtect = 0;
  do
  {
    if ( !*(_DWORD *)(v5 + 16) || dword_4043D0 )
      break;
    if ( a3 == GetModuleHandleA((LPCSTR)v6 + *(_DWORD *)(v5 + 12)) )
    {
      for ( lpAddress = (char *)v6 + *(_DWORD *)(v5 + 16); lpAddress; lpAddress = (char *)lpAddress + 4 )
      {
        if ( *(_DWORD *)lpAddress == a1 )
        {
          VirtualProtect(lpAddress, 4u, 4u, &flOldProtect);
          *(_DWORD *)lpAddress = a2;
          VirtualProtect(lpAddress, 4u, flOldProtect, 0);
          dword_4043D0 = 1;
          break;
        }
      }
    }
    v5 += 20;
  }
  while ( !dword_4043D0 );
  return dword_4043D0;
}
```

```c
int __stdcall sub_401650(int a1, int a2, int a3, int a4, int a5)
{
  *(_BYTE *)(a2 + 1822) = 6;
  *(_BYTE *)(a2 + 1713) = 6;
  dword_4043DC(a1, a2, a3, a4, a5);
  sub_4017C0(dword_4043DC, sub_401650, hModule);
  return 0;
}
```

- 这里可以看到把文件中其中两个字节改成了6,后面有用

- 执行完函数之后，有个`ExitProcess`，直接退出进程，再次调用`TLS_Callback`，这次进入第二个`if`

- `sub_401410`函数中调用了hook过的`WriteFile`函数，即修改了上述两个6，可以这时候再ida打开tmp文件，可以发现6原来是xxtea中右移的值

- `CreateProcessA`创建了新的进程，`sub_401510`函数实现了当前进程对子进程的调试

- `sub_401510`函数实现了该进程对子进程的调试监控

```c
BOOL __cdecl sub_401510(LPCSTR lpFileName, int a2)
{
  CONTEXT Context; // [esp+8h] [ebp-33Ch] BYREF
  int v4[23]; // [esp+2D4h] [ebp-70h] BYREF
  HANDLE hThread; // [esp+330h] [ebp-14h]
  int v6; // [esp+334h] [ebp-10h]
  int v7; // [esp+338h] [ebp-Ch]
  int v8; // [esp+33Ch] [ebp-8h]
  int v9; // [esp+340h] [ebp-4h]

  v4[22] = *(_DWORD *)a2;
  hThread = *(HANDLE *)(a2 + 4);
  v6 = *(_DWORD *)(a2 + 8);
  v7 = *(_DWORD *)(a2 + 12);
  v9 = 1;
  while ( v9 )
  {
    WaitForDebugEvent(&DebugEvent, 0xFFFFFFFF);
    if ( DebugEvent.dwDebugEventCode == 1 )
    {
      qmemcpy(v4, &DebugEvent.u, 0x54u);
      v8 = v4[0];
      if ( v4[0] == 0xC0000005 )
      {
        memset(&Context, 0, sizeof(Context));
        Context.ContextFlags = 65543;
        GetThreadContext(hThread, &Context);
        Context.Eip += 5;
        Context.Eax ^= 0x1B207u;
        SetThreadContext(hThread, &Context);
      }
    }
    if ( DebugEvent.dwDebugEventCode == 5 )
    {
      dword_404440 = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
      v9 = 0;
    }
    ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, 0x10002u);
  }
  Sleep(0x64u);
  return DeleteFileA(lpFileName);
}
```

- 当子进程发生`0xC0000005`异常（即内存读写异常）时，利用`GetThreadContext`获取子进程的上下文，修改Eip和Eax的值
- 对应的异常触发可在tmp文件中找到

```wasm
.text:0040122D                 mov     eax, [ebp-4]
.text:00401230                 xor     ebx, ebx
.text:00401232                 mov     [ebx], ebx
.text:00401234                 mov     eax, [ebp-4]
.text:00401237                 pop     ebx
.text:00401238                 mov     esp, ebp
.text:0040123A                 pop     ebp
.text:0040123B                 retn
```

- `xor ebx ebx`之后ebx中的值为0，后一句取ebx的地址，触发了异常，进行了上述操作，最终效果是给xxtea解密的delta又异或上了`0x1B207u`

- 异常处理过后，tmp继续执行，可以看到进行的是个xxtea加密

- 有一个点需要注意，tmp是作为子进程被调试的，`is_debugger_present`应为1

- 解密得到前半段flag，粘个脚本，xxtea加解密脚本引自官方

```c
#include <stdint.h>
#include <stdio.h>
#define DELTA 479354212
//delta = ((0x9E3779B9 ^ 0x12345678 ^0x90909090 ^ 0x7b) + 12345) ^ 111111
#define MX (((z >> 6 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)
    { /* Coding Part */
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)
    { /* Decoding Part */
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}
int main()
{
    unsigned int enc_flag[] = {0x6B7CE328, 0x4841D5DD, 0x963784DC, 0xEF8A3226, 0x0776B226};
    char flag[40];
    unsigned int key[] = {0x12, 0x90, 0x56, 0x78};
    btea(enc_flag, -5, key);
    for(int i = 0; i < 20; i++){
        flag[i] = *((char*)enc_flag + i);
    }
    puts(flag);
}   
// 
```

- `sub_401510`函数的返回值`dword_404440`正常情况应为1

- 于是进入相应if语句

- `sub_4012C0`函数对内存中一段数据进行了xxtea加密

```c
int __cdecl sub_4012C0(_DWORD *a1, int a2, int a3)
{
  int v3; // ecx
  int v4; // eax
  int v5; // edx
  int result; // eax
  int v7; // [esp+8h] [ebp-1Ch]
  int v8; // [esp+10h] [ebp-14h]
  unsigned int v9; // [esp+14h] [ebp-10h]
  unsigned int v10; // [esp+1Ch] [ebp-8h]
  unsigned int i; // [esp+20h] [ebp-4h]

  v8 = 52 / a2 + 6;
  v9 = 0;
  v10 = a1[a2 - 1];
  do
  {
    v9 += dword_404058;
    v7 = (v9 >> 2) & 3;
    for ( i = 0; i < a2 - 1; ++i )
    {
      v3 = ((v10 ^ *(_DWORD *)(a3 + 4 * (v7 ^ i & 3))) + (a1[i + 1] ^ v9)) ^ (((16 * v10) ^ (a1[i + 1] >> 3))
                                                                            + ((4 * a1[i + 1]) ^ (v10 >> 5)));
      v4 = a1[i];
      a1[i] = v3 + v4;
      v10 = v3 + v4;
    }
    v5 = (((v10 ^ *(_DWORD *)(a3 + 4 * (v7 ^ i & 3))) + (*a1 ^ v9)) ^ (((16 * v10) ^ (*a1 >> 3))
                                                                     + ((4 * *a1) ^ (v10 >> 5))))
       + a1[a2 - 1];
    a1[a2 - 1] = v5;
    result = v5;
    v10 = v5;
    --v8;
  }
  while ( v8 );
  return result;
}
```

- 解密可得后半段flag，脚本如下，xxtea加解密脚本引自官方

```c
#include <stdint.h>
#include <stdio.h>
#define DELTA 0x9E3779B9

#define MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)
    { /* Coding Part */
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)
    { /* Decoding Part */
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}
int main()
{
    unsigned int enc_flag[] = {0x9021A921,0x0F53B3060,0x8E88A84E,0x43635AD5,0x0AC119239};
    char flag[40];
    unsigned int key[] = {0x12, 0x34, 0x56, 0x78};
    btea(enc_flag, -5, key);
    for(int i = 0; i < 20; i++){
        flag[i] = *((char*)enc_flag + i);
    }
    puts(flag);
}    
// 3e90c91c02e9b40b78b}
```

- flag`miniLctf{cbda59ff59e3e90c91c02e9b40b78b}`

## CyberServer

- 咕咕咕
- 等我啥时候能写个这玩意再回来看吧

