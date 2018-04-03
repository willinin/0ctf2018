# 0ctf2018 babyheap

很简单的一个套路题，看到libc2.24就感觉是和`_IO_FILE`相关的虚表检查。

用chunk extend 泄露libc，然后unsortbin attack + FSOP + bypass vtabel check。

直接利用34c3 300的wp就可以了。
