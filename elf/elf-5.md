---
title: Linux 动态链接过程
date: 2016-10-21 09:03:34
tags:
categories:
decription:
---

文中描述了动态链接的详细过程，基于x86_64平台。
<!--more-->

## 动态链接 ##

## 内核加载可执行程序 ##
内核加载可执行程序做一些基本检查后，查找程序头为PT_INTERP的头，也就是解释器的路径。
注意INTERP的头，内核会检查GNU_STACK头，查看是否可以在栈中执行指令。
内核加载可执行程序的时候从sesction为.interp中读取解释器
```
objdump -s -j .interp a.out

Contents of section .interp:
 400200 2f6c6962 36342f6c 642d6c69 6e75782d  /lib64/ld-linux-
 400210 7838362d 36342e73 6f2e3200           x86-64.so.2.
```
先看看可执行程序的头：
```
readelf -l a.out
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001c0 0x00000000000001c0  R E    8
  INTERP         0x0000000000000200 0x0000000000400200 0x0000000000400200
                 0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000006b4 0x00000000000006b4  R E    200000
  LOAD           0x00000000000006b8 0x00000000006006b8 0x00000000006006b8
                 0x00000000000001ec 0x0000000000000200  RW     200000
  DYNAMIC        0x00000000000006e0 0x00000000006006e0 0x00000000006006e0
                 0x0000000000000190 0x0000000000000190  RW     8
  NOTE           0x000000000000021c 0x000000000040021c 0x000000000040021c
                 0x0000000000000044 0x0000000000000044  R      4
  GNU_EH_FRAME   0x00000000000005e8 0x00000000004005e8 0x00000000004005e8
                 0x000000000000002c 0x000000000000002c  R      4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     8

```
然后内核会通过加载LOAD的头进行内存映射，如下：
```
cat /proc/12350/maps

00400000-00401000 r-xp 00000000 08:08 8913487                            /opt/workspace/test_new/a.out
00600000-00601000 rw-p 00000000 08:08 8913487                            /opt/workspace/test_new/a.out
332c400000-332c420000 r-xp 00000000 08:03 61                             /lib64/ld-2.12.so
332c61f000-332c620000 r--p 0001f000 08:03 61                             /lib64/ld-2.12.so
332c620000-332c621000 rw-p 00020000 08:03 61                             /lib64/ld-2.12.so
332c621000-332c622000 rw-p 00000000 00:00 0
332c800000-332c98a000 r-xp 00000000 08:03 14814                          /lib64/libc-2.12.so
332c98a000-332cb8a000 ---p 0018a000 08:03 14814                          /lib64/libc-2.12.so
332cb8a000-332cb8e000 r--p 0018a000 08:03 14814                          /lib64/libc-2.12.so
332cb8e000-332cb8f000 rw-p 0018e000 08:03 14814                          /lib64/libc-2.12.so
332cb8f000-332cb94000 rw-p 00000000 00:00 0
7ffff7fea000-7ffff7fed000 rw-p 00000000 00:00 0
7ffff7ffd000-7ffff7ffe000 rw-p 00000000 00:00 0
7ffff7ffe000-7ffff7fff000 r-xp 00000000 00:00 0                          [vdso]
7ffffffea000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
我们在之前的头中看到LOAD的头如下：
```
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000006b4 0x00000000000006b4  R E    200000
  LOAD           0x00000000000006b8 0x00000000006006b8 0x00000000006006b8
                 0x00000000000001ec 0x0000000000000200  RW     200000
```
需要注意的是，内核取得虚拟内存地址是VirtAddr进行内存映射，将对应的头在文件中的内容映射到指定地址，第一个是0x0000000000400000，第二个是0x00000000006006b8。和mapping中一致，LOAD的对齐地址是0x200000，内存页的对齐地址为0x1000(4KB)。所以结束和起始地址会做对齐操作。

后续加载解释器，看看解释器ld-2.12.so的头：
```
Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x000000332c400000 0x000000332c400000
                 0x000000000001f388 0x000000000001f388  R E    200000
  LOAD           0x000000000001fb60 0x000000332c61fb60 0x000000332c61fb60
                 0x0000000000001448 0x0000000000001628  RW     200000
  DYNAMIC        0x000000000001fdf0 0x000000332c61fdf0 0x000000332c61fdf0
                 0x0000000000000190 0x0000000000000190  RW     8
  NOTE           0x00000000000001c8 0x000000332c4001c8 0x000000332c4001c8
                 0x0000000000000024 0x0000000000000024  R      4
  GNU_EH_FRAME   0x000000000001cd24 0x000000332c41cd24 0x000000332c41cd24
                 0x000000000000060c 0x000000000000060c  R      4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     8
  GNU_RELRO      0x000000000001fb60 0x000000332c61fb60 0x000000332c61fb60
                 0x00000000000004a0 0x00000000000004a0  R      1

```
LOAD的加载和之前一样。注意ld没有INTERP头。
看看ld的头：
```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x332c400b00
  Start of program headers:          64 (bytes into file)
  Start of section headers:          154952 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         7
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 30
```
从上面可以看出执行的地址是0x332c400b00(某些情况下内核会调整真正执行的地址)。反编译ld后,重点看这段：
```
objdump -d ld-2.12.so

000000332c400b00 <_start>:
  332c400b00:   48 89 e7                mov    %rsp,%rdi
  332c400b03:   e8 28 06 00 00          callq  332c401130 <_dl_start>

```
从解释程序ld的头**Entry point address**属性，可以知道，首先执行的是ld的_start。然后_dl_start：
所以我们知道解释器的程序为/lib64/ld-linux-x86-64.so.2，这个程序负责对加载的可执行程序进行解释。
解释器的其实地址是_dl_start,这个函数在glibc中。然后看一下这个程序,前面不看了，看重点，下面是_dl_start函数的部分代码：

```C
glibc-2.12.2\elf\rtld.c:

  /* Figure out the run-time load address of the dynamic linker itself.  */
  bootstrap_map.l_addr = elf_machine_load_address ();
  /* Read our own dynamic section and fill in the info array.  */
  bootstrap_map.l_ld = (void *) bootstrap_map.l_addr + elf_machine_dynamic ();
  elf_get_dynamic_info (&bootstrap_map, NULL);
```

先看第一个函数：
```C
static inline Elf64_Addr __attribute__ ((unused))
elf_machine_load_address (void)
{
  Elf64_Addr addr;

  /* The easy way is just the same as on x86:
       leaq _dl_start, %0
       leaq _dl_start(%%rip), %1
       subq %0, %1
     but this does not work with binutils since we then have
     a R_X86_64_32S relocation in a shared lib.

     Instead we store the address of _dl_start in the data section
     and compare it with the current value that we can get via
     an RIP relative addressing mode.  Note that this is the address
     of _dl_start before any relocation performed at runtime.  In case
     the binary is prelinked the resulting "address" is actually a
     load offset which is zero if the binary was loaded at the address
     it is prelinked for.  */

  asm ("leaq _dl_start(%%rip), %0\n\t"
       "subq 1f(%%rip), %0\n\t"
       ".section\t.data.rel.ro\n"
       "1:\t.quad _dl_start\n\t"
       ".previous\n\t"
       : "=r" (addr) : : "cc");

  return addr;
}
```
备注描述的很清楚为什么这样做，我们这里主要介绍指令执行。在.data.rel.ro的section保存编译的_dl_start虚拟地址。真正做计算的时候通过%rip相对寻址得到_dl_start加载到内存的地址，然后减去编译的_dl_start虚拟地址，就是其偏移量。一般情况下，这个都返回0。
而第二个函数elf_machine_dynamic ()返回的是.dynamic的地址。加上偏移地址就是真正的内存加载地址。
我们现在知道了加载的偏移地址，dynamic部分的加载地址。继续看_dl_start：
```C
glibc-2.12.2\elf\rtld.c:

  elf_get_dynamic_info (&bootstrap_map, NULL);

glibc-2.12.2\elf\dynamic-link.h:
inline void __attribute__ ((unused, always_inline))
elf_get_dynamic_info (struct link_map *l, ElfW(Dyn) *temp)
{
  ElfW(Dyn) *dyn = l->l_ld;
  ElfW(Dyn) **info;
#if __ELF_NATIVE_CLASS == 32
  typedef Elf32_Word d_tag_utype;
#elif __ELF_NATIVE_CLASS == 64
  typedef Elf64_Xword d_tag_utype;
#endif

#ifndef RTLD_BOOTSTRAP
  if (dyn == NULL)
    return;
#endif

  info = l->l_info;

  while (dyn->d_tag != DT_NULL)
    {
      if ((d_tag_utype) dyn->d_tag < DT_NUM)
	info[dyn->d_tag] = dyn;
      else if (dyn->d_tag >= DT_LOPROC &&
	       dyn->d_tag < DT_LOPROC + DT_THISPROCNUM)
	info[dyn->d_tag - DT_LOPROC + DT_NUM] = dyn;
      else if ((d_tag_utype) DT_VERSIONTAGIDX (dyn->d_tag) < DT_VERSIONTAGNUM)
	info[VERSYMIDX (dyn->d_tag)] = dyn;
      else if ((d_tag_utype) DT_EXTRATAGIDX (dyn->d_tag) < DT_EXTRANUM)
	info[DT_EXTRATAGIDX (dyn->d_tag) + DT_NUM + DT_THISPROCNUM
	     + DT_VERSIONTAGNUM] = dyn;
      else if ((d_tag_utype) DT_VALTAGIDX (dyn->d_tag) < DT_VALNUM)
	info[DT_VALTAGIDX (dyn->d_tag) + DT_NUM + DT_THISPROCNUM
	     + DT_VERSIONTAGNUM + DT_EXTRANUM] = dyn;
      else if ((d_tag_utype) DT_ADDRTAGIDX (dyn->d_tag) < DT_ADDRNUM)
	info[DT_ADDRTAGIDX (dyn->d_tag) + DT_NUM + DT_THISPROCNUM
	     + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM] = dyn;
      ++dyn;
    }

#define DL_RO_DYN_TEMP_CNT	8

#ifndef DL_RO_DYN_SECTION
  /* Don't adjust .dynamic unnecessarily.  */
  if (l->l_addr != 0)
    {
      ElfW(Addr) l_addr = l->l_addr;
      int cnt = 0;

# define ADJUST_DYN_INFO(tag) \
      do								      \
	if (info[tag] != NULL)						      \
	  {								      \
	    if (temp)							      \
	      {								      \
		temp[cnt].d_tag = info[tag]->d_tag;			      \
		temp[cnt].d_un.d_ptr = info[tag]->d_un.d_ptr + l_addr;	      \
		info[tag] = temp + cnt++;				      \
	      }								      \
	    else							      \
	      info[tag]->d_un.d_ptr += l_addr;				      \
	  }								      \
      while (0)

      ADJUST_DYN_INFO (DT_HASH);
      ADJUST_DYN_INFO (DT_PLTGOT);
      ADJUST_DYN_INFO (DT_STRTAB);
      ADJUST_DYN_INFO (DT_SYMTAB);
# if ! ELF_MACHINE_NO_RELA
      ADJUST_DYN_INFO (DT_RELA);
# endif
# if ! ELF_MACHINE_NO_REL
      ADJUST_DYN_INFO (DT_REL);
# endif
      ADJUST_DYN_INFO (DT_JMPREL);
      ADJUST_DYN_INFO (VERSYMIDX (DT_VERSYM));
      ADJUST_DYN_INFO (DT_ADDRTAGIDX (DT_GNU_HASH) + DT_NUM + DT_THISPROCNUM
		       + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM);
# undef ADJUST_DYN_INFO
      assert (cnt <= DL_RO_DYN_TEMP_CNT);
    }
#endif
  if (info[DT_PLTREL] != NULL)
    {
#if ELF_MACHINE_NO_RELA
      assert (info[DT_PLTREL]->d_un.d_val == DT_REL);
#elif ELF_MACHINE_NO_REL
      assert (info[DT_PLTREL]->d_un.d_val == DT_RELA);
#else
      assert (info[DT_PLTREL]->d_un.d_val == DT_REL
	      || info[DT_PLTREL]->d_un.d_val == DT_RELA);
#endif
    }
#if ! ELF_MACHINE_NO_RELA
  if (info[DT_RELA] != NULL)
    assert (info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela)));
# endif
# if ! ELF_MACHINE_NO_REL
  if (info[DT_REL] != NULL)
    assert (info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel)));
#endif
#ifdef RTLD_BOOTSTRAP
  /* Only the bind now flags are allowed.  */
  assert (info[VERSYMIDX (DT_FLAGS_1)] == NULL
	  || info[VERSYMIDX (DT_FLAGS_1)]->d_un.d_val == DF_1_NOW);
  assert (info[DT_FLAGS] == NULL
	  || info[DT_FLAGS]->d_un.d_val == DF_BIND_NOW);
  /* Flags must not be set for ld.so.  */
  assert (info[DT_RUNPATH] == NULL);
  assert (info[DT_RPATH] == NULL);
#else
  if (info[DT_FLAGS] != NULL)
    {
      /* Flags are used.  Translate to the old form where available.
	 Since these l_info entries are only tested for NULL pointers it
	 is ok if they point to the DT_FLAGS entry.  */
      l->l_flags = info[DT_FLAGS]->d_un.d_val;

      if (l->l_flags & DF_SYMBOLIC)
	info[DT_SYMBOLIC] = info[DT_FLAGS];
      if (l->l_flags & DF_TEXTREL)
	info[DT_TEXTREL] = info[DT_FLAGS];
      if (l->l_flags & DF_BIND_NOW)
	info[DT_BIND_NOW] = info[DT_FLAGS];
    }
  if (info[VERSYMIDX (DT_FLAGS_1)] != NULL)
    {
      l->l_flags_1 = info[VERSYMIDX (DT_FLAGS_1)]->d_un.d_val;

      if (l->l_flags_1 & DF_1_NOW)
	info[DT_BIND_NOW] = info[VERSYMIDX (DT_FLAGS_1)];
    }
  if (info[DT_RUNPATH] != NULL)
    /* If both RUNPATH and RPATH are given, the latter is ignored.  */
    info[DT_RPATH] = NULL;
#endif
}
```
前段就是根据elf规范加载dynamic。然后调节加载到内存的地址。后面就是做一些校验和赋值操作。

## 分析动态链接过程 ##
内核加载各类文件，elf文件的入口点为_start，linux建立一个单独的进程，指定可执行程序的入口点是_start，先看一个简单的例子：

```asm
00000000004003e0 <_start>:
  4003e0:	31 ed                	xor    %ebp,%ebp
  4003e2:	49 89 d1             	mov    %rdx,%r9
  4003e5:	5e                   	pop    %rsi
  4003e6:	48 89 e2             	mov    %rsp,%rdx
  4003e9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4003ed:	50                   	push   %rax
  4003ee:	54                   	push   %rsp
  4003ef:	49 c7 c0 f0 04 40 00 	mov    $0x4004f0,%r8
  4003f6:	48 c7 c1 00 05 40 00 	mov    $0x400500,%rcx
  4003fd:	48 c7 c7 ca 04 40 00 	mov    $0x4004ca,%rdi
  400404:	e8 af ff ff ff       	callq  4003b8 <__libc_start_main@plt>
  400409:	f4                   	hlt    
  40040a:	90                   	nop
  40040b:	90                   	nop
```

通过汇编指令，知道入口点程序调用的是<__libc_start_main@plt>符号链接，那这个地址在那边呢？
编译器gcc会生成在可执行的文件中生成一个.plt的section，这个section指向动态链接具体的寻址程序，
gcc编译器并不知道我们需要对应符号的地址，这些地址都是通过ld程序进行寻址加载的。gcc增加了一个.plt
的section来完成这个定位动态链接库或可执行程序对应符号在操作系统中的地址，也就是说这些地址是动态的。
所以，我们通过objdump -d -j .plt a.out 可以得到如下的信息：

```asm
Disassembly of section .plt:

00000000004003a8 <__libc_start_main@plt-0x10>:
  4003a8:	ff 35 d2 04 20 00    	pushq  0x2004d2(%rip)        # 600880 <_GLOBAL_OFFSET_TABLE_+0x8>
  4003ae:	ff 25 d4 04 20 00    	jmpq   *0x2004d4(%rip)        # 600888 <_GLOBAL_OFFSET_TABLE_+0x10>
  4003b4:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004003b8 <__libc_start_main@plt>:
  4003b8:	ff 25 d2 04 20 00    	jmpq   *0x2004d2(%rip)        # 600890 <_GLOBAL_OFFSET_TABLE_+0x18>
  4003be:	68 00 00 00 00       	pushq  $0x0
  4003c3:	e9 e0 ff ff ff       	jmpq   4003a8 <_init+0x18>

00000000004003c8 <time@plt>:
  4003c8:	ff 25 ca 04 20 00    	jmpq   *0x2004ca(%rip)        # 600898 <_GLOBAL_OFFSET_TABLE_+0x20>
  4003ce:	68 01 00 00 00       	pushq  $0x1
  4003d3:	e9 d0 ff ff ff       	jmpq   4003a8 <_init+0x18>

```
和具体调用的程序看，重点看<__libc_start_main@plt>：
```asm
00000000004003b8 <__libc_start_main@plt>:
  4003b8:	ff 25 d2 04 20 00    	jmpq   *0x2004d2(%rip)        # 600890 <_GLOBAL_OFFSET_TABLE_+0x18>
  4003be:	68 00 00 00 00       	pushq  $0x0
  4003c3:	e9 e0 ff ff ff       	jmpq   4003a8 <_init+0x18>
```

第一段代码采用了x64的rip相对寻址，通过这个机制，我们的代码可以做成与具体地址无关的应用程序，先看看第一段指令具体的意思：
首先%rip表示当前执行指令的位置，即0x4003b8。而0x2004d2(%rip)这种间接寻址的写法是AT&T的写法，在AT&T的内存寻址写法为：disp(base, index, scale)【intel写法：[BASE+INDEX*SCALE+DISP]】。所以这里base=%rip，这里%rip表示执行完此指令后的下一条指令地址0x4003be，disp=0x2004d2，所以计算的内容为：0x4003be+0x2004d2=0x600890，正好是标注的内容。
其次，**jmpq   *0x2004d2(%rip)**整个指令表示的是从内存地址0x600890中取得8个字节，然后把这8个字节作为内存地址进行跳转，那么这个内存地址的内容是什么了？
这就引出了ld中的另外一个概念got，got可以看成一个字节数组，在x64系统中，元素大小是8byte，got中存放了具体对应函数的地址，可执行程序中的地址都是从这个字节数组中获取内存地址进行跳转的。
```asm
0000000000600878 <_GLOBAL_OFFSET_TABLE_>:
  600878:	e0 06 60 00 00 00 00 00 00 00 00 00 00 00 00 00     ..`.............
	...
  600890:	be 03 40 00 00 00 00 00 ce 03 40 00 00 00 00 00     ..@.......@.....
```
上面就是got的内容，存放在.got.plt的section中，我们看看内存地址0x600890是什么内容，注意intel是字节序为小端，也就是说从低地址到高地址内容为：be 03 40 00 00 00 00 00，而真正在intel中加载表示的内容为0x00000000004003be。我们这样就知道jmpq其实跳转的地址是0x4003be，其实就是jmpq的下一条指令。我们刚刚不是说这个地方存放的应该是真正执行符号的地址，为什么是下一条指令的地址呢。
这正是ld设计的巧妙之处，我们继续往下看。
```asm
  4003be:	68 00 00 00 00       	pushq  $0x0
  4003c3:	e9 e0 ff ff ff       	jmpq   4003a8 <_init+0x18>
```
这段指令就是将0压入栈。然后执行0x4003a8。通过之前的反编译，0x4003a8的内用也在.plt，这个是什么东东。
```asm
00000000004003a8 <__libc_start_main@plt-0x10>:
  4003a8:	ff 35 d2 04 20 00    	pushq  0x2004d2(%rip)        # 600880 <_GLOBAL_OFFSET_TABLE_+0x8>
  4003ae:	ff 25 d4 04 20 00    	jmpq   *0x2004d4(%rip)        # 600888 <_GLOBAL_OFFSET_TABLE_+0x10>
  4003b4:	0f 1f 40 00          	nopl   0x0(%rax)
```
这个地址就是plt的第一个跳转函数，你会发现所有动态符号执行的都是这个地址的指令，为什么会这样？
plt的第一段指令都是一样，就是这段指令，我们可以猜测这段指令及其重要，一定和找到对应内存地址有关。
一步步来看，这段指令压入栈，然后执行jmpq指令。先看看这个时候栈的内容
```
[  ...  ]
[   0   ]
[   0   ]  
[       ]  <---rsp
```
上面栈是方法调用使用的，下面的是动态链接过程使用中压入的两个元素，一个是pushq  $0x0指令压入，一个是pushq  0x2004d2(%rip)压入。
然后就执行指令jmpq   *0x2004d4(%rip)，即内存地址0x600888，这个地方是什么呢？我们在gdb中看看：
```asm
(gdb) x/20i 0x332c4147d0
   0x332c4147d0 <_dl_runtime_resolve>:	sub    $0x38,%rsp
   0x332c4147d4 <_dl_runtime_resolve+4>:	mov    %rax,(%rsp)
   0x332c4147d8 <_dl_runtime_resolve+8>:	mov    %rcx,0x8(%rsp)
   0x332c4147dd <_dl_runtime_resolve+13>:	mov    %rdx,0x10(%rsp)
   0x332c4147e2 <_dl_runtime_resolve+18>:	mov    %rsi,0x18(%rsp)
   0x332c4147e7 <_dl_runtime_resolve+23>:	mov    %rdi,0x20(%rsp)
   0x332c4147ec <_dl_runtime_resolve+28>:	mov    %r8,0x28(%rsp)
   0x332c4147f1 <_dl_runtime_resolve+33>:	mov    %r9,0x30(%rsp)
   0x332c4147f6 <_dl_runtime_resolve+38>:	mov    0x40(%rsp),%rsi
   0x332c4147fb <_dl_runtime_resolve+43>:	mov    0x38(%rsp),%rdi
   0x332c414800 <_dl_runtime_resolve+48>:	callq  0x332c40df60 <_dl_fixup>
   0x332c414805 <_dl_runtime_resolve+53>:	mov    %rax,%r11
   0x332c414808 <_dl_runtime_resolve+56>:	mov    0x30(%rsp),%r9
   0x332c41480d <_dl_runtime_resolve+61>:	mov    0x28(%rsp),%r8
   0x332c414812 <_dl_runtime_resolve+66>:	mov    0x20(%rsp),%rdi
   0x332c414817 <_dl_runtime_resolve+71>:	mov    0x18(%rsp),%rsi
   0x332c41481c <_dl_runtime_resolve+76>:	mov    0x10(%rsp),%rdx
   0x332c414821 <_dl_runtime_resolve+81>:	mov    0x8(%rsp),%rcx
   0x332c414826 <_dl_runtime_resolve+86>:	mov    (%rsp),%rax
   0x332c41482a <_dl_runtime_resolve+90>:	add    $0x48,%rsp
```
内存地址0x332c4147d0是0x600888存放的内容。通过反编译的我们可以知道，0x600888即_dl_runtime_resolve的内存地址，那么这个内存地址什么时候放入的呢？又是用来干什么的呢？
先来看看_dl_runtime_resolve是干什么的，_dl_runtime_resolve的源代码在glibc中，有兴趣可以了解一下这个过程，这里从反编译角度看。
_dl_runtime_resolve上面的代码主要保存了上下文，需要重点看的是
```asm
   0x332c4147f6 <_dl_runtime_resolve+38>:	mov    0x40(%rsp),%rsi
   0x332c4147fb <_dl_runtime_resolve+43>:	mov    0x38(%rsp),%rdi
```
执行上面的之后，栈中是什么样的，如下：
```
[   ...   ]   <---(rsp)
[    0    ]   <---0x40(rsp)  ;pushq  $0x0
[    0    ]   <---0x38(rsp)  ;pushq  0x2004d2(%rip)
[   r9    ]   <---0x30(rsp)  
[   r8    ]   <---0x28(rsp)
[   rdi   ]   <---0x20(rsp)
[   rsi   ]   <---0x18(rsp)
[   rdx   ]   <---0x10(rsp)    
[   rcx   ]   <---0x8(rsp)
[   rax   ]   <---rsp
```
上面的栈内容和指令一 一对应。然后调用_dl_fixup函数。
