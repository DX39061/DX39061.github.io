# linux进程基础


## 进程状态

一台linux机器上运行着多个进程，每个进程在同一时间都处在一种特定的状态，称为`进程状态`，常见的进程状态如下：

### R(TASK_RUNNING)，可执行状态

由于一个单核CPU在同一时间只能执行一个进程，所以并不是所有处于可执行状态的进程都正在被CPU执行，处于可执行状态的进程会被添加到CPU的执行队列中，由进程调度器决定每一刻真正执行的是哪一个进程。

### S(TASK_INTERRUPTIBLE)，可中断的睡眠状态

处于这个状态的进程在等待着某些事件的发生（如等待socket连接、等待信号量等），属于挂起（睡眠）状态。使用top命令可以发现绝大多数进程都处于这个状态

### D(TASK_UNINTERRUPTIBLE)，不可中断的睡眠状态

与S状态类似，进程处于挂起（睡眠）状态，但此时进程无法被中断/杀死，不会响应进程信号（如SIGKILL），常用于系统底层某些不能被打断的进程

### T(TASK_STOPPED)，暂停状态

向处于`TASK_RUNNING`状态的进程发送一个`SIGSTOP`信号可以强制使进程停止，来到`TASK_STOPPED`状态，当接收到`SIGCONT`信号时，进程将重新回到`TASK_RUNNING`状态

### t(TASK_TRACED)，正在被跟踪状态

此状态下的进程也会暂停下来，等待跟踪它的调试进程对它进行操作。与`TASK_STOPPED`状态不同，此状态不会相应`SIGCONT`信号，只有调试进程调用`PTRACE_CONT`、`PTRACE_DETACH`或进程退出时被调试的进程才能恢复`TASK_RUNNING`状态

### Z(TASK_DEAD-EXIT_ZOMBIE)退出状态，成为僵尸进程

大致可分为两种情况：

- 子进程退出但父进程并未及时释放子进程，称为`僵尸状态`

- 父进程退出，但子进程仍然存在，称为`孤儿状态`

### X(TASK_DEAD-EXIT_DEAD)退出状态，进程即将被销毁

进程被置于此状态时，接下来立即会被完全释放，此状态持续时间十分短暂

## 进程信号

控制进程状态的更新、变换需要系统发出信号，即`进程信号`，进程信号列表可以使用`kill -l`查看，

进程信号调控进程状态，大致如下图：

![7shwmsnui7.png](https://img.dx3906.cloud/imgs/7shwmsnui7.png)

注：图中Running和Ready同属`TASK_RUNNING`状态

## 进程创建

linux用户态创建进程常用fork、vfork、clone三个函数

### 原理

三者都是依托父进程创建新的子进程，函数返回值在不同进程中值不同，在子进程中返回0，在父进程中返回子进程pid，返回值为负数则创建子进程失败。

三者区别在于对进程空间的使用。fork函数创建的子进程会复制一份父进程的进程空间，vfork函数创建的子进程与父进程使用同一份进程空间，而clone函数可选是否共用各种资源。

fork和vfork函数还有另外一个区别：fork函数创建的子进程与父进程同时运行，先后顺序随即。而vfork函数保证子进程先运行，只有当子进程退出时才会运行父进程，确保不会发生同时读写内存等竞争问题。

下面针对fork和vfork函数进行尝试：

### 使用fork函数

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    int num = 1;
    pid_t pid = fork(); // 创建子进程

    if (pid == -1) {
        puts("failed to create child process");
        return -1;
    } else if (pid == 0) {
        puts("in child process");
        printf("pid = %d\n", getpid());
        printf("num = %d\n", num);
        num = 10;
        printf("num is modified by child process\nnow num = %d\n\n", num);
    } else {
        sleep(1); // 确保父进程运行到这时子进程已完成了对num的修改
        puts("in parent process");
        printf("pid = %d\n", getpid());
        printf("child process pid is %d\n", pid);   // 父进程中fork函数返回值为子进程pid
        printf("num = %d\n\n", num);
    }
}
```

程序输出：s

```
in child process
pid = 61209
num = 1
test is modified by child process
now num = 10

in parent process
pid = 61208
child process pid is 61209
num = 1
```

可以看到在子进程中修改了num的值，对父进程的num没有影响，正是因为父、子进程进程空间相互独立

### vfork函数

#### 使用exit函数正常退出子进程

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    int num = 1;
    pid_t pid = vfork();

    if (pid == -1) {
        puts("failed to create child process");
        return -1;
    } else if (pid == 0) {
        puts("in child process");
        printf("pid = %d\n", getpid());
        printf("num = %d\n", num);
        num = 10;
        printf("test is modified by child process\nnow num = %d\n\n", num);
        exit(0); // 退出子进程
    } else {
        puts("in parent process");
        printf("pid = %d\n", getpid());
        printf("child process pid is %d\n", pid);   // 父进程中vfork函数返回值为子进程pid
        printf("num = %d\n\n", num);
    }
}
```

程序输出：

```
in child process
pid = 62770
num = 1
test is modified by child process
now num = 10

in parent process
pid = 62769
child process pid is 62770
num = 10
```

可以看到在子进程中修改num的值，在父进程中输出num的值也改变了，正是因为两进程共用一块进程空间

#### 不能使用return退出子进程

将上个例子中使用`exit(0)`退出子进程改为使用`return 0`试试效果：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    int num = 1;
    pid_t pid = vfork();

    if (pid == -1) {
        puts("failed to create child process");
        return -1;
    } else if (pid == 0) {
        puts("in child process");
        printf("pid = %d\n", getpid());
        printf("num = %d\n", num);
        num = 10;
        printf("test is modified by child process\nnow num = %d\n\n", num);
        return 0;
    } else {
        puts("in parent process");
        printf("pid = %d\n", getpid());
        printf("child process pid is %d\n", pid);   // 父进程中vfork函数返回值为子进程pid
        printf("num = %d\n\n", num);
    }
}
```

程序输出：

```
in child process
pid = 65039
num = 1
test is modified by child process
now num = 10

in parent process
pid = 65038
child process pid is 65039
num = -1431084768
```

可以发现父进程输出的num出现了错误。

这是因为子进程使用return返回意味着子进程中的main函数结束了，main函数的栈会被回收，然后子进程结束。因为父进程与子进程共享这个栈，而栈中存放的num值已不存在，故会打印出错。

更进一步，如果把return也去掉，会发现效果是一样的，因为函数正常结束，一样会进行栈回收。

总结来说，子进程退出一般都要使用exit函数

#### 使用exec函数族调起新的进程

exec函数族分别包括以下函数：

```c
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ..., char * const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execve(const char *path, char *const argv[], char *const envp[]);
```

其中`execve`是linux的一个系统调用，其他函数都是对它的封装。功能是根据指定的路径或文件名找到相应的可执行文件，使用该可执行文件的代码段、数据段、堆栈数据替换当前进程中的数据，进行执行。

要注意的是，使用exec函数族不会创建新的进程，不会改变pid，只是替换了当前进程空间的数据。

回归正题，最开始只有一个fork函数可以用来创建新进程，但很多程序中仅仅是在新进程中使用了exec函数族调起了新的进程，这时fork函数复制整个父进程的进程空间就成了浪费。于是后来才产生了vfork函数。

实践一下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    int num = 1;
    pid_t pid = vfork();

    if (pid == -1) {
        puts("failed to create child process");
        return -1;
    } else if (pid == 0) {
        puts("in child process");
        printf("pid = %d\n", getpid());
        printf("num = %d\n", num);
        num = 10;
        printf("test is modified by child process\nnow num = %d\n\n", num);
        char *argv[] = {"ls", "-l", "/", NULL};
        execve("/bin/ls", argv, NULL);  // 调起ls进程
        perror("error exec");   // 打印错误
    } else {
        sleep(1);
        puts("in parent process");
        printf("pid = %d\n", getpid());
        printf("child process pid is %d\n", pid);   // 父进程中vfork函数返回值为子进程pid
        printf("num = %d\n\n", num);
    }
    return 0;
}
```

程序输出：

```
in child process
pid = 70303
num = 1
test is modified by child process
now num = 10

total 33570236
lrwxrwxrwx   1 root   root            7 Oct 19 05:01 bin -> usr/bin
drwxr-xr-x   4 root   root         4096 Nov 12 10:30 boot
drwxr-xr-x  23 root   root         4360 Nov 17 10:09 dev
drwxr-xr-x 133 root   root        12288 Nov 17 14:21 etc
drwxr-xr-x   3 root   root         4096 Jan 23  2022 home
lrwxrwxrwx   1 root   root            7 Oct 19 05:01 lib -> usr/lib
lrwxrwxrwx   1 root   root            7 Oct 19 05:01 lib64 -> usr/lib
drwx------   2 root   root        16384 Jan 23  2022 lost+found
drwxr-xr-x   3 root   root         4096 Oct 19 00:40 mnt
drwxr-xr-x  28 root   root         4096 Nov 11 01:15 opt
dr-xr-xr-x 429 root   root            0 Nov 17 10:09 proc
drwxr-x---  26 root   root         4096 Nov 10 18:35 root
drwxr-xr-x  34 root   root          940 Nov 17 14:19 run
lrwxrwxrwx   1 root   root            7 Oct 19 05:01 sbin -> usr/bin
drwxr-xr-x   4 root   root         4096 Jan 23  2022 srv
-rw-------   1 root   root  34359738368 Nov  2 23:05 swapfile
dr-xr-xr-x  13 root   root            0 Nov 17 10:09 sys
drwxrwxrwt  19 root   root          580 Nov 17 17:22 tmp
drwxr-xr-x  11 root   root         4096 Nov 17 01:09 usr
drwxr-xr-x  15 root   root         4096 Nov 17 10:09 var
in parent process
pid = 70302
child process pid is 70303
num = 10
```

可以看到`ls`进程被正常调起并正常输出

但这里还有一个问题，按理说execve之后进程空间被完全被替换，回到父进程后应该无法正常运行，这里牵扯到一些内核机制问题，参考 https://www.zhihu.com/question/515280466

## Reference

[Linux系统之进程状态 - 腾讯云开发者社区-腾讯云](https://cloud.tencent.com/developer/article/1568077)

[进程线程常见基础问题 | Whatbeg&#39;s blog](http://whatbeg.com/2019/06/05/processthread.html)

https://book.itheima.net/course/223/1277519158031949826/1277528003525484545

https://www.zhihu.com/question/515280466

