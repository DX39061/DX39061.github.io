# 版本控制（git）


# 版本控制（git）

## 为什么需要版本控制

- 方便管理不同功能的多个版本

- 方便出问题后回滚

- 方便多人协作

## git数据模型

### #要存什么？

- 目录结构（tree）

- 文件详细内容（blob对象/数据对象）

- 各个版本/提交的历史记录（snap快照）

- 历史记录关联/先后顺序（有向无环图）

```
o <-- o <-- o <-- o <---- o
            ^            /
             \          v
              --- o <-- o
```

### #伪代码表示

```
// 文件就是一组数据
type blob = array<byte>

// 一个包含文件和目录的目录
type tree = map<string, tree | blob>

// 每个提交都包含一个父辈，元数据和顶层树
type commit = struct {
    parent: array<commit>    // 父节点
    author: string           // 作者
    message: string          // 提交信息
    snapshot: tree           // 目录结构
}
```

### #对象和内存寻址

- 在git中blob、tree、commit都是object（对象）

- git在存储数据时，所有的对象都会基于他们的`SHA1`散列值（通常为40位16进制值）进行寻址，由此任意一个提交都会被一串字符串唯一标识

### #一些特殊的引用

SHA1运算的结果40位16进制数难以记忆，所以为了更加方便的获取一些对象的地址，git对一些哈希赋予了人类可读的名字，叫做对象的`引用`，常见的引用有：

- HEAD：指向当前工作区所在的分支/提交

- master/main：仓库主分支

- origin：远程仓库

## 明确git和github的关系

- git 不依赖于 github 存在。

- github可以作为一个远程git仓库，进行代码托管，方便多人协作

## git本地基本工作流

### #三个区域

- 本地目录（工作区）

    打开文件夹实际看到的

- 暂存区（索引区）

    在文件被提交至本地仓库之前所处的位置

- 本地仓库（.git文件夹）

    存储着各种历史版本

### #操作流程

- 初始化git仓库

    `git init`

- 新建/修改/删除文件

    `vim/rm/...`

    `git status`：查看git仓库状态

- 把文件添加到暂存区

    `git add`

 为什么需要暂存区？

> 您开发了两个独立的特性，然后您希望创建两个独立的提交，其中第一个提交仅包含第一个特性，而第二个提交仅包含第二个特性。

简单来说就是可以自由地控制提交的内容，使用更灵活

- 将暂存区中的文件提交到本地仓库
  
  `git commit` 
  
  `git log`：查看commit信息

- etc... 

## git branch（分支）

### #为什么需要分支？

- 隔离开发主线，确认无误后再进行分支合并

- 分离不同功能，使版本管理更有条理

- 多人协作更方便

### #命令行操作

- 详细请看`git help branch`，这里仅进行简单罗列

- git branch -v：查看现有分支

- git branch <name>：创建分支

- git checkout <name>：切换分支

- git merge <name>：合并分支

## git remote（远程仓库）

将代码保存在远程仓库，方便多人协作，方便他人拉取代码

### #明确

- git remote仓库与 本地仓库 是完全一样的结构，一样有commit/branch等概念

- 注意如果在本地创建了新分支，远程仓库也需要创建新分支（一般是push同时创建新分支）

### #命令行操作

- git remote -v：查看远程仓库信息

- git remote add <name> <url>：添加一个远程仓库

- git remote rm <name>：删除一个远程仓库

- git clone <url>：克隆一个远程仓库到本地

- git push <remote repo> <local branch>:<remote branch>：向远程仓库推送代码

- git fetch <remote repo> <remote branch>：从远程仓库拉取代码

- git pull = git fetch + git merge

## git常见场景

### #本地初始化仓库提交到github

- `git init`初始化git仓库

- 注意添加`.gitignore`文件忽略隐私文件、多余文件

- `git add`、`git commit`...

- `git push` 到远程仓库

### #clone远程仓库并在本地编辑

- 复制远程仓库url

- 本地进行`git clone`

- 进行开发

- push到远程仓库

### #fork仓库并发起pr(pull request)

- 本地拉取github仓库

- 创建新分支，在新分支上进行开发

- push到github仓库

- 提交pr, 等待原仓库管理员合并

## tips

### #撤销commit

- 未push到remote
  
  - git reset --soft
  
     把commit撤销到暂存区
  
  - git reset --mixed
    
    把commit撤销到工作区（同时撤销git commit和git add）

- 已push到remote
  
  - git reset --hard
    
    清除撤销commit的一切记录
  
  - git revert
    
    生成新的撤销commit

### #merge和rebase

- merge：合并两分支，保留所有提交记录

- rebase：**变基**，改变一部分commit记录，使git log更加简洁

- rebase -i：常用于重排commit

