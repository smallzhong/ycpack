# ycpack
 傀儡进程加密壳 滴水三期课后作业

## 代码下载

考虑到国内git clone非常缓慢，我将代码传了一份在百度网盘上，如果通过github无法成功下载代码可以使用百度网盘下载，压缩包一共32kb大小。

链接：https://pan.baidu.com/s/1MWxS-vE1jL7VJ6o_SKPHew 
提取码：1111 

## 项目说明

+ 本项目是[滴水三期视频](https://www.bilibili.com/video/BV1yt41127Cd)的一个课后作业，是使用 **傀儡进程** 方法写的一个 **玩具** 壳

+ 壳主体的工作步骤如下

  1. 读取主模块的数据
  2. 解密：得到原来的PE文件
  3. 以挂起的形式创建进程： `CreateProcess` ，要创建的进程，就是壳子本身				
  4. 获取外壳程序的Context，后面要用.					
  5. 卸载外壳程序.					
  6. 在指定的位置分配空间：位置就是src的ImageBase  大小就是Src的SizeOfImage					
  7. 如果成功，将Src的PE文件拉伸 复制到该空间中					
  8. 如果申请空间失败，但有重定位表：在任意位置申请空间，然后将PE文件拉伸、复制、修复重定位表。					
  9. 如果第6步申请空间失败，并且还没有重定位表，直接返回：失败。					
  10. 修改外壳程序的Context:					
  
  	+  将Context的ImageBase 改成 Src的ImageBase
  	+  将Context的OEP 改成 Src的OEP		
  11. 设置Context 并恢复主线程					
  12. 终止外壳程序，解壳过程结束.	
  
+  加壳机的工作步骤如下

  1. 获取Shell程序的路径				
  2. 获取src程序的路径			
  3. 将src程序读取到内存中，加密							
  4. 在Shell程序中新增一个节，并将加密后的src程序追加到Shell程序的新增节中						
  5. 加壳过程完毕

## 编译环境

XP系统 + VC6 

> 注意：不能用Visual Studio来编译。在VS中有些函数的参数会从 `LPSTR` 变为宽字符的 `LPWSTR` ，而且在VS中 `TCHAR` 是 `WCHAR` 而在VC6中 `TCHAR` 是 `CHAR` 。所以在VS中一定编译不过。

## 使用方法

**注：只支持给32位程序加壳，不能给64位程序加壳！**

+ 将加壳机和壳本体编译出来（或者在 [**release**](https://github.com/smallzhong/ycpack/releases) 中下载已经编译好的EXE），其中 **packer.exe** 是加壳机， **ycpack_shell.exe** 是壳本体。双击加壳机输入壳本体和需要加壳的源程序的位置，并输入需要保存的位置即可生成加壳后的程序。

![看不见图片请爬梯子](https://cdn.jsdelivr.net/gh/smallzhong/picgo-pic-bed@master/image-20200818204950233.png)

+ 加壳后可正常运行。

![看不见图片请爬梯子](https://cdn.jsdelivr.net/gh/smallzhong/picgo-pic-bed@master/image-20200818205007366.png)

## 待完成功能

- [ ] 在加壳的时候通过加密算法（如异或）给源程序加密
- [ ] 当 `VirtualAllocEx` 分配空间失败时判断是否有重定位表并重新申请空间
- [x] 隐藏console，在打开加壳后的程序时不会弹出黑框框

## 鸣谢

+ 本项目中使用了部分[@adezz](https://github.com/adezz)用户的[Shell-Of-Water](https://github.com/adezz/Shell-Of-Water)项目中的代码