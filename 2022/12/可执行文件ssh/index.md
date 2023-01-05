# 可执行文件概述和ssh使用简介


## 可执行文件相关

### #什么是可执行文件

- exe（PE）文件、ELF文件

- 二进制文件

- 可直接运行

### #可执行文件的来龙去脉

**C源代码** ---预处理、编译--> **汇编代码** ---汇编编译---> **可重定向目标文件**（机器码） ---链接---> **可执行文件**

- 编译工具链
  
  - gcc（cpp、cc、as、ld）：编译源文件
  
  - make/cmake：批量编写编译指令

- 静态链接/动态链接，静态库(.a.lib)/动态库(.so.dll)
  
  - 静态链接：把库代码全部写入可执行文件
  
  - 动态链接：只将一些标记写入可执行文件

### #可执行文件如何被执行

- 操作系统为其创建一个新进程（process）

- 加载器（loader）将可执行文件复制到新进程的内存空间中

- CPU执行机器码

### #可执行文件为何无法执行

- CPU架构不同

    x86、Arm、Risc-V

    无法识别异架构机器码

- 操作系统不同
  
  win、linux、mac
  
  无法装载可执行文件、库不同、系统调用不同

### #硬要执行怎么办

- 虚拟环境(虚拟机、wsl2)：开销大、但准确率高

- 辅助装载、指令翻译(wine、wsl1)：开销小、但错误多

### #题外话--从可执行文件看跨平台解决方案

计算机领域问题经典解：加一层

- vm(virtual machine)语言

    python、java、js与浏览器环境

    vm负责在不同的平台给CPU翻译成适合的指令

- Qt(一个C++库)
  
  编写代码时使用Qt**统一封装**的库代替**某种系统**的特定库
  
  在进行普通的C代码编译之前，Qt先将Qt的库替换成特定系统需要的特定库
  
  一套代码、多次编译

## ssh相关

### #基本概念

- ssh：是一套网络协议，用于`安全的网络服务`和`加密远程登录`

- openssh：是实现ssh协议的主流开源软件

- linux机器上的ssh命令：用于连接远程服务器的命令行程序

- sshd：是ssh服务端的后台守护程序

- 基本命令：`ssh user@ip -p port`

### #如何保障登录时的安全性

- 不能明文传输口令/数据

- 保证密钥交换的安全性

- **客户端**与**服务器**的互相身份确认

### #关于非对称加密算法

- 密钥有公钥和私钥之分

- 明文用公钥加密得到密文

- 密文用私钥解密得到明文

- 公钥和私钥是一一配对的，只有用公钥唯一对应的私钥才能解开密文

### #基于口令的登录验证

<img title="" src="https://img.dx3906.cloud/imgs/ssh%E5%9F%BA%E4%BA%8E%E5%8F%A3%E4%BB%A4%E7%9A%84%E7%99%BB%E5%BD%95%E9%AA%8C%E8%AF%81.png" alt="ssh基于口令的登录验证.png" width="489">

### #基于公钥的免密登录

<img src="https://img.dx3906.cloud/imgs/ssh%E5%9F%BA%E4%BA%8E%E5%85%AC%E9%92%A5%E7%9A%84%E5%85%8D%E5%AF%86%E7%99%BB%E5%BD%95.png" title="" alt="ssh基于公钥的免密登录.png" width="514">

- 客户端（本地）生成公私钥：`ssh-keygen -t ed25519`
  
  [关于加密方式的对比](https://marcofranssen.nl/upgrade-your-ssh-security)

- 将公钥发送给服务器：`ssh-copy-id user@ip`

- 修改服务器sshd配置，允许公钥登录：

```shell
> sudo vim /etc/ssh/sshd_config
> 找到 PubkeyAuthentication选项，配置为yes，并删除行注释
# 修改完成后重启sshd服务
> sudo systemctl restart sshd
```

### #对服务器验证防止中间人攻击

是**客户端**对**服务器**身份的验证，防止中间人拦截流量，假冒服务器

第一次使用ssh登录服务器时，需要你手动验证服务器指纹信息：

```shell
> ssh dx3906@ip
The authenticity of host 'ip (ip)' can't be established.
ED25519 key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxx.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

此时可使用如下命令计算SHA256：

```shell
> ssh-keyscan -t ed25519 ip | ssh-keygen -lf -
# ip:22 SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
256 SHA256:xxxxxxxxxxxxx ip (ED25519)
```

上下两个SHA256一致，则可证明确实在与服务器通信

### #一些有用的配置

#### 客户端设置主机别名

每次进行ssh登录都要输入`ssh user@ip -p port`未免有点麻烦，可以通过配置`～/.ssh/config`简化命令写法，配置语法如下：

```
Host my_vps
    User user
    Hostname ip
    Port port
```

之后就可以使用`ssh my_vps`代替先前的命令

#### 服务端安全配置

修改`/etc/ssh/sshd_config`文件，保存修改并重启sshd服务`sudo systemctl restart sshd`

- 修改服务端口防止爆破

    人人都知道ssh默认端口为22且必有一个叫root的用户    

- 禁止root登录

    `PermitRootLogin no`

- 禁止密码登录（只能用公钥登录）
  
  `PasswordAuthentication no`

