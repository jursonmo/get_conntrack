## put conntrack info in tcp or udp payload 
### this module is to get data conntrack info and put orignal dst ip in tcp or udp payload , userspace can get the orignal dst ip of the data, so i can do something like sock5 
1. socket listen at 192.168.1.1:8888.( 192.168.1.1 is local ip)
2. redirect data to listen socket:iptables -t nat -A PREROUTING -d xxx  -j DNAT --to-destination 192.168.1.1:8888
3. the new socket can get conntrack info from tcp or udp payload, see example udp_getconn.c

## learn from ALG (ftp change tcp payload)
1. [ALG在nf_conntrack的实现](https://github.com/jursonmo/get_conntrack/issues/1)


