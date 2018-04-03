#0ctf 2018 House of Cards

还是太穷了，想象力不够。
其实就是一个跨目录读的逻辑漏洞，这类漏洞应该在渗透这种偏web的题目里比较常见，但是把我这个穷小子吊起来打了。

看下官方出题人的思路：

```
————————————————————————————————————————————————————————————
    🃏   🄷 🄾 🅄 🅂 🄴  🄾 🄵  🄲 🄰 🅁 🄳 🅂   🃏
————————————————————————————————————————————————————————————
1♠ Write
2♥ Read
3♦ Go
4♣ Exit
>
```
You can checkout angelboy's neat exploit code.

It's not about heap at all.

You have to exploit with 2 IP.

IP A to leak the whole stack to file l4w by supplying Size data = -1 . Hang it.

Meanwhile, go to IP B, using stack overflow, to spray the string like:

'/////////{ip_A}\0' * 0x1337

to overwrite env REMOTE_HOST

On the current session B, you got the sandbox path as IP A directory. From now on, you can read the leaked-stack file l4w, then send it to A.

Go back to A, parse the file then you have full stack content including: stack cookie, return address, PIE , libc ... and simply overwrite return address to system.

