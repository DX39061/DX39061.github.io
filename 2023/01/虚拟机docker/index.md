# 虚拟机&Docker


## 虚拟机(Virtual Machine)

从使用的角度讨论几个简单概念，不涉及具体的虚拟化技术

### #为什么会有虚拟机

- 使用现有硬件资源干更多的事
  
  最常用，如在windows上装linux运行elf文件

- 获得隔离环境
  
  运行不受信任的软件，如病毒

- 售卖云计算资源
  
  阿里云/腾讯云/华为云等各种vps提供商

### #虚拟机基本架构

理论层面来看：

- 在一台普通的机器中，软件如何使用硬件资源进行运作？
  
  笼统地说，操作系统内核调动硬件资源，分配给用户程序使用
  
  ![](https://img.dx3906.cloud/imgs/os-structure.png)

- 尝试在操作系统内核和硬件之间加一层
  
  虚拟机监视器（VMM）负责在不同系统内核之间协调硬件资源，隔离环境，并监控其运行状态
  
  ![vm1png](https://img.dx3906.cloud/imgs/vm-1.png)

### #两种虚拟机方案

#### type1：直接运行在硬件上

我们在上面的想法实际变成了type1虚拟机。VMM直接与硬件交互，协调、分配硬件资源。一般为虚拟机数量较多的企业环境使用

- hyper-V：win10自带，开启后，windows主机就变成了第一个vm

- kvm：linux内核的一个模块。

- 优势：
  
  - 灵活。可以在不同的物理资源之间移动，而不会影响用户
  
  - 安全性高。不经过os层直接操作硬件，减少了vmm被攻击的可能
  
  - 动态分配资源。vmm实际运行时只分配足够客户机使用的资源。vps超售

- 劣势：
  
  - 功能有限。相比type2提供的功能较少
  
  - 管理较难。

#### type2：运行于存在的os上

不直接接触硬件，受主机操作系统控制，作为一个用户程序运行在os上，个人使用较多。

- vmware：虚拟机软件老大哥。功能丰富，使用者众多。但专业版收费

- virtual-box：免费且做得很不错，某些功能不如vmware，但实测在linux上使用体验更好

- 优势：
  
  - 便于管理。管理简单，适合个人使用
  
  - 功能丰富。软件通常会提供丰富的工具，文件拖拽、剪贴板同步等等

- 劣势：
  
  - 性能较低。性能不如type1，容易出现延迟
  
  - 安全性较低。攻击者可能会利用操作系统的漏洞来访问虚拟机
  
  - 无法动态分配资源。需要预分配资源，虚拟机开启状态下无法更改

![](https://i.stack.imgur.com/TAMdL.png)

## Docker

### #容器技术简介

在很多虚拟化场景下，我们的目的其实只是要运行某个应用，如果使用虚拟机构建一整个操作系统未免太过浪费，且不利于打包与移植

容器技术可以按软件所需将系统资源划分到孤立的组中。

### #容器技术发展

- chroot：
  
  是unix系统的一个命令。作用于正在运行的进程和它的子进程，改变其根目录。被操作的应用程序无法访问根目录之外的内容，从而unix就有了这种能力：为每个进程提供一个隔离的文件系统。chroot被认为是容器技术的鼻祖。

- namespace机制：
  
  linux内核用来隔离资源的方式。通过namespace可以让一个进程只看到与自己相关的一部分资源，是对全局资源的一种封装隔离。

- Cgroups：
  
  全称Control Groups，原名Process Containers，后被并入linux内核。用来限制、统计、隔离一组进程的资源使用。

- LXC：
  
  全称Linux Containers。使用namespace做资源隔离，解决能用什么资源的问题。使用Cgroups做资源控制，解决能用多少资源的问题。

- k8s：
  
  全称Kubernetes。是用于自动部署、扩展和管理“容器化（containerized）应用程序”的开源系统，它旨在提供“跨主机集群的自动部署、扩展以及运行应用程序容器的平台”。它支持一系列容器工具，包括Docker等

### #Docker简介

Docker是目前最受欢迎的容器技术。

- 轻量、便携、隔离、性能损耗小

- Docker使用linux kernel的namespace做资源隔离（能用什么资源），使用Cgroups做资源控制（能用多少资源）

- windows和其它平台要使用docker，需要安装一个特殊改进的linux kernel（docker安装包自带）。

### #Docker三大基本概念

- 镜像（image）：一个只读的文件和文件夹组合，包含所有镜像启动所需的基础文件和配置信息。

- 容器（Container）：是镜像的运行实体，运行着真正的应用进程。与主机隔离，无法看到主机上的进程、环境变量、网络等信息。

- 仓库（Repository）：类似于代码仓库，用于存放docker镜像。Dockerhub是官方的公开镜像仓库，自己也可以构建自己的私有仓库。

### #Docker基本架构

docker采用CS架构，由docker守护进程（Docker daemon）作为server和Docker命令行工具作为client组成。

- Dockerd：docker引擎，真正干活的程序

- Docker client：接收用户输入的命令，与Dockerd通信

![](https://pic4.zhimg.com/80/v2-3c73d6d9a294506faa20ed6e0c10a513_720w.jpg)

### #实例：拉取Docker镜像并启动容器

注：如果想要使用非root用户操作docker,可以创建docker用户组，具体方法请自行搜索

```shell
sudo systemctl start docker # 确保dockerd守护进程开启
docker pull nginx # 拉取nginx镜像
docker run  -d       -p         8080:80             nginx
#         后台运行  指定端口映射   主机端口:容器内端口    镜像名
```

浏览器打开`127.0.0.1:8080`即可看到nginx页面

### #Dockerfile

由基础镜像，逐步构建自己的镜像。以下为一个最简单的Dockerfile例子:

- Dockerfile：

```docker
# 指定基础镜像
FROM nginx
# 替换nginx默认index.html的内容
RUN echo "<h1>RX IS GOD!</h1>" > /usr/share/nginx/html/index.html
```

- 使用Dockerfile构建镜像

```shell
docker build  .       -t  mynginx:v1
#  构建镜像  当前目录 指定标签   name:tag
```

- 使用镜像创建并运行容器

```shell
docker run  -d       -p         8081:80            mynginx:v1
#         后台运行  指定端口映射   主机端口:容器内端口    镜像名:tag   (不加tag会默认找mynginx:latest)
```

### #Docker Compose

注：在大多数发行版中，docker compose需要单独安装

用于定义和运行**多容器**应用程序的工具。使用`docker-compose.yml`配置文件定义服务。部署多容器项目时，方便一条命令启动、停止、管理整个项目

例如一个前后端分离的web项目，可以分成前端、后端、数据库、缓存服务器等多个容器，统一管理

下面用一个单容器的例子简单介绍下docker compose的常用语法

- docker-compose.yml(遵循yaml配置文件语法):

```docker
# 指定docker-compose 版本
version: '3'
# 开始定义services
services:
# 定义一个叫nginx的服务
  nginx:
# docker会去当前目录(.)下寻找Dockerfile构建镜像
    build: .    
# 指定端口映射
    ports:
      - "8082:80"
```

- 运行服务

```shell
docer-compose up -d # 后台运行
```

- 重新构建所用镜像

```shell
docker-compose build
```

- 查看log与停止、重启服务

```shell
docker-compose logs # 查看运行日志 
docker-compose stop # 停止
docker-compose restart # 重启
```

