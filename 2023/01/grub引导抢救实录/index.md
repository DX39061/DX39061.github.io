# Archlinux Grub引导抢救实录


## 我只想扬了系统更新报错

刚开始其实并没想折腾内核，只是想解决系统更新一些看不懂的报错

archlinux在每次进行系统更新时，如果涉及内核相关，就会触发pacman钩子，调用mkinitcpio脚本重新构建内核镜像，这部分详见 https://wiki.archlinuxcn.org/wiki/Mkinitcpio （这也是我在排错时才知道的），但我的机器每次都会输出几行Error，看得人十分不爽：

```
==> ERROR: module not found: `nvidia'
==> ERROR: module not found: `nvidia_modeset'
==> ERROR: module not found: `nvidia_uvm'
==> ERROR: module not found: `nvidia_drm'
```

有过之前两次搞崩显卡无法开机的经历，以及一切都还能用，之前一直没管过它，但这次想刨根问底了，经过一段时间google，在archwiki上找到了[这一篇文章](https://bbs.archlinux.org/viewtopic.php?id=277580)，问题几乎和我一模一样。

最后发现我之前不知道什么时候安装过`linux-zen`这个包，同时我一直在使用的是`linux`这个包的主线内核，在上述调用mkinitcpio脚本的过程中，会同时尝试构建linux和linux-zen两种内核的镜像，linux镜像一直能够正常构建，出问题的只是linux-zen镜像的构建。

到这反而激起了我的兴趣，去了解了一下各种内核，贴一个[archwiki的介绍](https://wiki.archlinuxcn.org/wiki/%E5%86%85%E6%A0%B8)，发现linux-zen内核可能会有更好的性能表现，且对wine的某些体验会有较大的提升。于是我抱着好奇的心态准备换个内核

## grub直接进bios反复鬼畜

先装好了`linux-zen`和`linux-zen-headers`两个包，然后为了解决上面找不到nvidia模块的问题需要把`nvidia`换成`nvidia-dkms`，装完之后就没有ERROR了

然后尝试reboot进入zen内核，发现grub菜单并没有zen内核的选项，查了查发现需要重新生成grub配置，即`sudo grub-mkconfig -o /boot/grub/grub.cfg`。从这，噩梦开始

reboot之`Welcome to grub`一闪而过，然后电脑关机，再开机直接进入了bios。bios里选择继续启动，就会重复上面的动作，一闪而过、关机、开机、进bios，反复鬼畜

wiki上发现了和我相同的[遭遇](https://bbs.archlinuxcn.org/viewtopic.php?id=12560)，但是并没有解决，不了了之了。到处搜索发现基本都是教你grub引导出错进入`grub shell`该怎么办，但我能用的只有bios，连能执行命令的地方都没有。另外的办法还可以使用装系统的启动盘引导启动，但我手边根本没有，只有一个装在移动硬盘里的windows，它能救我吗？

## windows删grub配置进grub-shell

在bios选择移动硬盘启动成功了开起来了windows。第一想法是grub.cfg有问题，想要修改grub.cfg，但其实这个文件只能用`sudo grub-mkconfig -o /boot/grub/grub.cfg`生成，但在windows上显然无法执行命令。

这时突然想到前面看过很多误删grub.cfg的解决方案，直接死马当活马医，使用`linuxReader`挂载了linux的硬盘，给grub.cfg扬了。重新reboot成功进入了grub shell，但这时我也发现了另一个问题：我进不了bios了。这意味着如果我无法在grub shell解决问题，恐怕就只能重装系统了

## 手动引导进入系统以及重装grub

又是查了半天，学会了如何手动引导，archwiki上有简略的命令可以[参考](https://wiki.archlinuxcn.org/zh-hans/GRUB)，但如果想我一样对`linux``initrd`等命令不熟悉还需要多查查才能搞明白。其中需要避坑的是有些文章时间久远，写的是grub1的命令，而现在大家用的基本都是grub2，grub1的命令诸如`root``kernel`等在grub2中被启用或替代

这里放一篇比较详细的[介绍](https://zhuanlan.zhihu.com/p/412008178)，看完基本就能理解如何使用这几条命令了，在这就不赘述。至此，我的arch终于活过来了，成功进入系统。

至于如何修复grub，由于我没有耐心去看grub的文档了，索性重装。重新安装了grub包，然后重新执行了`sudo grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=archlinux`，然后生成配置文件`sudo grub-mkconfig -o /boot/grub/grub.cfg`。reboot之后成功进入了grub菜单，并能够选择linux和linux-zen内核。

到底grub为什么会出错不想再深究了，总有很多玄学问题没有答案。

## 题外话

深刻地感受到了arch社区的强大、wiki的细致

能够自己动手一步步探索、解决问题，算是终于成了一个合格的arch用户

