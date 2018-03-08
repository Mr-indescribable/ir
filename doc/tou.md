## TCP over UDP (TOU) 使用说明

### 概述

ir提供了一个简陋的TOU解决方案，其初衷是为了分散传输TCP流（UDP分路模式将会在短期内完成），以达到降低TCP流量特征的目的。
不同于KCP协议，ir的TOU实现没有考虑过任何与加速有关的事项，所做的这一切都不是为了加速TCP流。
大多数情况下，开启TOU模式之后TCP会减速，主要表现为传输速率下降（如果你没有堆够机器的话）。
当然，需要加速请上[kcptun](https://github.com/xtaci/kcptun)（或者也可以大把砸钱，上4线8线12线）。

---------------------------

### 工作方式

local TCPServer在接收到来自应用程序的数据之后会通过TOUAdapter将这块数据转换成若干个TOU数据包。
然后将这些TOU数据包通过UDP协议发送给local UDPServer，local UDPServer会对这些包进行二次封装并遵循ir的基础UDP协议发送至remote。
UDP数据包到达remote之后，remote UDPServer会将合法的TOU数据包发送给remote TCPServer。
而后remote TCPServer通过TOUAdatper将这些UDP包转换成TCP流，并发送至目标服务器。
回程逆向同理。

+ 示意图：

```

    +--------+  TCP  +--------+  TCP  +---------+  UDP  +--------+
    |        | ----> | local  | ----> |         | ----> | local  |
    |  app   |       |  TCP   |       | adapter |       |  UDP   |
    |        | <---- | server | <---- |         | <---- | server |
    +--------+  TCP  +--------+  TCP  +---------+  UDP  +--------+
                                                          ^    |
                                                          |    |
                                                      UDP |    | UDP
                                                          |    |
                                                          |    V
    +--------+  TCP  +--------+  TCP  +---------+  UDP  +--------+
    |  dest  | ----> | remote | ----> |         | ----> | remote |
    |        |       |  TCP   |       | adapter |       |  UDP   |
    | server | <---- | server | <---- |         | <---- | server |
    +--------+  TCP  +--------+  TCP  +---------+  UDP  +--------+

```

这里的UDPServer是由启动脚本额外启动专供TOU使用的，也就是说，这个TOU-UDPServer需要单独占用一个端口。
在TOU模式下，服务端对外开放2个UDP端口，TCPServer和UDPServer之间通信使用的socket则是监听了本地回环地址127.0.0.1。

---------------------------

### 启动方式

ir-local 和 ir-remote 启动脚本现在加入了 --tou 参数，使用此参数即可进入TOU模式

----------------------------

### 配置项说明

+ UDP部分的配置项TOU\_UDP服务和基础UDP服务共享大部分配置，不共享的部分添加了"tou\_"前缀用以区分
+ 不共享的配置项有：udp\_multi\_remote, listen\_udp\_port

|Tag|                 字段名                  |                                   描述                                |
|---|-----------------------------------------|-----------------------------------------------------------------------|
| L |         tou\_remote\_tcp\_port          |          远端的TOU\_TCP服务所监听的端口，需要和远端配置保持一致       |
| L |         tou\_udp\_multi\_remote         |     与基础UDP配置中的udp\_multi\_remote同义，此项供TOU\_UDP服务使用   |
|L&R|         tou\_listen\_tcp\_port          |             与listen\_tcp\_port同义，此项供TOU\_TCP服务使用           |
|L&R|         tou\_listen\_udp\_port          |             与listen\_udp\_port同义，此项供TOU\_UDP服务使用           |
|L&R|               log\_file                 |               新增字段tou\_tcp和tou\_udp供2个TOU server使用           |
|L&R|          tou\_pkt\_max\_serial          |  TOU包的最大序号，由于部分功能尚未完善，所以目前需要保持在4294967295  |
|L&R|        tou\_tcp\_db\_max\_serial        | 数据块的最大序号，由于部分功能尚未完善，所以目前需要保持在4294967295  |
|L&R|              tou\_min\_tu               |   单位字节，最小传输单元，有足够数据时数据块的大小不允许小于这个数字  |
|L&R|              tou\_max\_tu               |         单位字节，最大传输单元，数据块的大小不允许大于这个数字        |
|L&R|              tou\_arq\_rto              |       包重传间隔时间，单位秒，建议取值为：实际延迟的1.2到2.0倍        |
|L&R|      tou\_max\_upstm\_window\_size      |                     单位字节，上行流的最大发送窗口大小                |
|L&R|      tou\_max\_dnstm\_window\_size      |                     单位字节，下行流的最大发送窗口大小                |
|L&R|          tou\_udp\_ctrl\_port           | TOU-UDPServer用于接收管控包的端口，监听于loop-back供其他本地Server使用|

+ 额外说明：

```

关于 tou_arq_rto 的额外说明：
        在实际运作中，并不会直接使用这个值作为RTO，而是在此基础上加上一个微小随机偏移后再作为RTO。


关于 tou_min_tu 和 tou_min_tu 的额外说明：
        表格中提及的数据块大小指来自TCP流的数据的切块大小。
        在发送TCP数据块之前，我们先要对其进行切割，实际上这2项配置指定的大小就是数据块切割时的大小上下限。


关于 tou_pkt_max_serial 和 tou_tcp_db_max_serial 的额外说明：
        TOU的数据包序号和数据块序号在每个TCP连接中是独立存在互不干扰的。

        由于偷懒(￣□￣)，所以还没有做serial到达上限之后重置的功能。暂时设置为4294967295以使其能长时间运行。
        不同于udp_multi_transmit_max_packet_serial，TOU的serial只是一个编号，用于保障数据块的有序性，大编号上限不会占用很多额外内存。
        以每秒10000个TOU包的发送速度来算，可以连续运行5天左右，但是实际使用中几乎不可能达不到平均每秒10000个TOU包。
        而不可描述先生制作ir的目的是为了能够让自己流畅地玩steam上的国际化网游（只是为了满足自己的需求而已），连续在线1周什么基本不可能。
        在已预期的使用场景下，单一一个TCP连接序号达到上限的可能实在是太低，所以就暂且先这样用着。
        Hmmmmm，所以......有需要的用户......你们懂的......自己fork过去改代码吧。
```

----------------------------------

### 配置样例

##### local

```json
{
	"remote_addr": "192.168.122.164",
	"tou_remote_tcp_port": 6040,
	"tou_udp_multi_remote": {"192.168.122.164": 6060, "192.168.122.23": 6060},

	"listen_addr": "127.0.0.1",
	"listen_udp_port": 60050,
	"tou_listen_tcp_port": 60040,
	"tou_listen_udp_port": 60060,

	"iv_len": 32,
	"cipher_name": "aes-256-gcm",
	"passwd": "An indescribable password",
	"udp_socket_max_idle_time": 60,
	"log_level": "info",
	"log_file": {"tcp": "/tmp/ir-tcp.log",
				 "udp": "/tmp/ir-udp.log",
				 "tou_tcp": "/tmp/ir-tou-tcp.log",
				 "tou_udp": "/tmp/ir-tou-udp.log"},
	"crypto_libpath": "/usr/lib/libcrypto.so.1.1",

	"udp_multi_remote": {"192.168.122.164": 6050, "192.168.122.23": 6050},

	"udp_multi_transmit_times": 1,
	"udp_multi_transmit_max_packet_serial": 32768,
	"udp_iv_change_rate": 0.001,
	"udp_min_salt_len": 4,
	"udp_max_salt_len": 32,

	"tou_pkt_max_serial": 4294967295,
	"tou_tcp_db_max_serial": 4294967295,
	"tou_min_tu": 1024,
	"tou_max_tu": 8192,
	"tou_arq_rto": 0.2,
	"tou_max_upstm_window_size": 32,
	"tou_max_dnstm_window_size": 96,
	"tou_udp_ctrl_port": 6061
}
```

##### remote

```json
{
	"listen_addr": "0.0.0.0",
	"listen_udp_port": 6050,
	"tou_listen_tcp_port": 6040,
	"tou_listen_udp_port": 6060,

	"cipher_name": "aes-256-gcm",
	"passwd": "An indescribable password",
	"udp_socket_max_idle_time": 60,
	"log_level": "info",
	"log_file": {"tcp": "/tmp/ir-tcp.log",
				 "udp": "/tmp/ir-udp.log",
				 "tou_tcp": "/tmp/ir-tou-tcp.log",
				 "tou_udp": "/tmp/ir-tou-udp.log"},
	"crypto_libpath": "/usr/local/lib64/libcrypto.so.1.1",

	"udp_multi_source": ["192.168.122.171", "192.168.122.23"],
	"udp_multi_transmit_times": 1,
	"udp_multi_transmit_max_packet_serial": 32768,
	"udp_min_salt_len": 4,
	"udp_max_salt_len": 32,

	"tou_pkt_max_serial": 4294967295,
	"tou_tcp_db_max_serial": 4294967295,
	"tou_min_tu": 1024,
	"tou_max_tu": 8192,
	"tou_arq_rto": 0.2,
	"tou_max_upstm_window_size": 32,
	"tou_max_dnstm_window_size": 96,
	"tou_udp_ctrl_port": 6061
}
```
