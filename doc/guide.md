## 使用说明

### 启动方式

由于不可描述先生比较懒，所以只写了2个基础启动脚本：ir-local和ir-remote. 将脚本中的config\_path变量的值修改为配置文件路径运行脚本即可启动

> 若需要命令行参数，pid文件等功能...... 自己改代码去

### 后台运行

ir的启动脚本并没有提供daemon模式，后台运行需要借助其它工具。一个简单的例子：setsid ./ir-remote

> 当然，你也可以DIY

### 配置文件

+ 配置文件的格式为json
+ 以下带有L标签的为local的可用配置，带有R标签的为remote的可用配置

|Tag|                 字段名                  |                                   描述                                |
|---|-----------------------------------------|-----------------------------------------------------------------------|
| L |              server\_addr               |                            指定远程服务器地址                         |
| L |           server\_tcp\_port             |                          指定远程服务端TCP端口                        |
| L |           server\_udp\_port             |                          指定远程服务端UDP端口                        |
|L&R|              listen\_addr               |                            指定本地监听地址                           |
|L&R|           listen\_tcp\_port             |                          指定本地监听的TCP端口                        |
|L&R|           listen\_udp\_port             |                          指定本地监听的UDP端口                        |
|L&R|             cipher\_name                |  加密方式。明细: ir.cryptor.openssl.OpenSSLCryptor.supported\_cipher  |
|L&R|                passwd                   |                            用于身份认证的密码                         |
|L&R|      udp\_socket\_max\_idle\_time       |                     UDP socket最大闲置时间，过期销毁                  |
|L&R|               log\_file                 |日志文件，不配置则输出至stdout，格式：{"tcp": "a.log", "udp": "b.log"} |
|L&R|               log\_level                |       日志级别，支持的选项有：debug, info, warn, warning, error       |
|L&R|            crypto\_libpath              |                             加密库所在路径                            |
|L&R|          udp\_min\_salt\_len            |                    指定UDP包头中salt随机长度的最小值                  |
|L&R|          udp\_max\_salt\_len            |                    指定UDP包头中salt随机长度的最大值                  |
| L |                iv\_len                  |                               指定IV长度                              |
| L |        udp\_iv\_change\_rate            |                          UDP通信中的IV变更机率                        |
| L |          udp\_multi\_remote             |       UDP多线路，多个远程服务器。格式：{ip0: port0, ip1: port1}       |
| R |          udp\_multi\_source             |            UDP多线路，多个可信的请求来源。格式：[ip0, ip1]            |
|L&R|      udp\_multi\_transmit\_times        |                          UDP多倍发包的发包倍率                        |
|L&R|udp\_multi\_transmit\_max\_packet\_serial|UDP包序号的最大值，用于过滤重复包，数值越大内存占用越高，最大4294967295|

-----------------------------------

### 工作模式以及配置样例

#### 普通透明代理

```
                        不可描述的物体

                               |
                               |
+-------+                      |                   +--------+
|       |                      |                   |        |
| local | ---------------------|------------------ | remote |
|       |            ^         |         ^         |        |
+-------+            |         |         |         +--------+
                     |         |         |    
                     |         |         |    
                     |                   |    
                     |                   |
                     +---------+---------+
                               |
                               |
                            此处可以
                            有个nat
```

> local

```json
{
  "server_addr": "1.1.1.1",
  "server_tcp_port": 10,
  "server_udp_port": 20,
  "listen_addr": "127.0.0.1",
  "listen_tcp_port": 100,
  "listen_udp_port": 200,
  "cipher_name": "aes-256-gcm",
  "passwd": "An indescribable password",
  "log_level": "info",
  "crypto_libpath": "/usr/lib/libcrypto.so.1.1",
  "udp_iv_change_rate": 0.001,
  "udp_socket_max_idle_time": 60,
}
```
 
> remote

```json
{
    "listen_addr": "0.0.0.0",
    "listen_tcp_port": 10,
    "listen_udp_port": 20,
    "cipher_name": "aes-256-gcm",
    "passwd": "An indescribable password",
    "log_level": "info",
    "crypto_libpath": "/usr/lib/libcrypto.so.1.1",
    "udp_socket_max_idle_time": 60, 
}
```

------------------------------------

#### UDP多线路

+ 通过使用多条线路多倍发包来抵抗UDP丢包。
+ 需要额外的nat中转节点，没有什么神奇的需求的话，建议用iptables nat
+ remote需要看到多个请求源
+ 不可描述先生使用的是2x1模式，也就是双线1倍发包，壕建议上4x1
+ 拓扑图例（以双线为例

```
可用拓扑0：墙内2个不同线路的中转节点
优点：最简单最方便最便宜的
缺点：remote节点直接暴露


                                  不可描述的物体

                                        |
                                        |
                 +--------+             |
                 |        |             |
                 |   nat  | ------------|-----------------------+
                 |        |             |                       |
                 +--------+             |                       |
                      ^                 |                       v
+-------+             |                 |                   +--------+
|       |             |                 |                   |        |
| local | ------------+                 |                   | remote |
|       |             |                 |                   |        |
+-------+             |                 |                   +--------+
                      v                 |                       ^
                 +--------+             |                       |
                 |        |             |                       |
                 |   nat  | ------------|-----------------------+
                 |        |             |
                 +--------+             |
                                        |
                                        |
                                        |
```

```
可用拓扑1：墙内一个中转节点，墙外2个不同线路的中转节点
优点：remote节点安全
缺点：若墙外节点使用的是优质线路，则费用较高，线路控制能力略微弱一些


                             不可描述的物体

                                   |
                                   |
                                   |            +--------+
                                   |            |        |
                      +------------|----------->|   nat  | -------+
                      |            |            |        |        |
                      |            |            +--------+        |
                      |            |                              v
+-------+         +-------+        |                          +--------+
|       |         |       |        |                          |        |
| local | ------->|  nat  |        |                          | remote |
|       |         |       |        |                          |        |
+-------+         +-------+        |                          +--------+
                      |            |                              ^
                      |            |            +--------+        |
                      |            |            |        |        |
                      +------------|----------->|   nat  | -------+
                                   |            |        |
                                   |            +--------+
                                   |
                                   |
                                   |
```

```
可用拓扑2：墙内外各2个中转节点，可能是玩网游的最优方案
优点：remote节点安全，最高的线路控制能力
缺点：要是能把花在线路上的钱都用到游戏上的话......


                             不可描述的物体

                                   |
                                   |
                  +--------+       |         +--------+
                  |        |       |         |        |
                  |   nat  |-------|-------->|   nat  | -------+
                  |        |       |         |        |        |
                  +--------+       |         +--------+        |
                      ^            |                           v
+-------+             |            |                       +--------+
|       |             |            |                       |        |
| local | ------------+            |                       | remote |
|       |             |            |                       |        |
+-------+             |            |                       +--------+
                      v            |                           ^
                  +--------+       |         +--------+        |
                  |        |       |         |        |        |
                  |   nat  |-------|-------->|   nat  | -------+
                  |        |       |         |        |
                  +--------+       |         +--------+
                                   |
                                   |
                                   |
```

> 还有很多其它的拓扑待使用者自己发掘。由于TCP只做了最基础的代理功能，所以以上拓扑中的TCP都是走单一线路的，具体怎么走就要看使用者的意愿了。

+ 配置样例

> local

```json
{
  "server_addr": "1.1.1.1",
  "server_tcp_port": 10,
  "listen_addr": "127.0.0.1",
  "listen_tcp_port": 100,
  "listen_udp_port": 200,
  "cipher_name": "aes-256-gcm",
  "passwd": "An indescribable password",
  "log_level": "info",
  "crypto_libpath": "/usr/lib/libcrypto.so.1.1",
  "udp_iv_change_rate": 0.001,
  "udp_socket_max_idle_time": 60,
  "udp_multi_remote": {"1.1.1.1": 20, "2.2.2.2": 20},
  "udp_multi_transmit_times": 2,
  "udp_multi_transmit_max_packet_serial": 65536
}
```
 
> remote

```json
{
    "listen_addr": "0.0.0.0",
    "listen_tcp_port": 10,
    "listen_udp_port": 20,
    "cipher_name": "aes-256-gcm",
    "passwd": "An indescribable password",
    "log_level": "info",
    "crypto_libpath": "/usr/lib/libcrypto.so.1.1",
    "udp_socket_max_idle_time": 60, 
    "udp_multi_source": ["3.3.3.3", "4.4.4.4"],
    "udp_multi_transmit_times": 2,
    "udp_multi_transmit_max_packet_serial": 65536
}
```

--------------------------------------

#### 单线路的UDP多倍发包

> 这个模式在设置之初是不在计划内的，并且也不推荐使用。单线路多倍发包在玩游戏遇到线路抽风的情况下该丢的包还是会丢，就算没丢延迟也会大大增加，使用2条延迟差距较小的不同线路比单一一条线路多倍发包的抗丢包抗抽风能力要好得多。
> 启用方式：udp\_multi\_remote和udp\_multi\_source只配一台服务器即可
