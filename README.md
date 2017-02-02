kcp-go-raw
----------

为了解决 ISP 或某猴米路由器对 UDP 可能的QOS问题,利用原始套接字实现了运行在伪装的 TCP 协议之上的 kcp-go   

注意事项  
-------

服务端在使用前需要设置 iptables 来避免内核返回的 RST 报文断开客户端的连接  
```
iptables -A OUTPUT -p tcp --sport <port> --tcp-flags RST RST -j DROP
```
