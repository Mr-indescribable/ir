#!/usr/bin/python3
import time
import socket

server_addr = '192.168.122.164'
server_port = 60051
timeout = 3    #s

report_temp = '%s bytes from %s:%d: seq=%s time=%s ms' % (
                '%d', server_addr, server_port, '%d', '%s')
statis_temp = '''
--- %s ping statistics ---
%s transmitted, %s received, %s loss, total time %s
rtt min/avg/max = %s/%s/%s ms''' % (server_addr,
                                    '%d', '%d', '%s', '%s',
                                    '%s', '%s', '%s')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(timeout)

rcv_flag = False
seq = 1
sent = 0
rcv = 0
total_time = 0    #ms
rtt_min = timeout * 1000    #ms
rtt_max = 0.0    #ms
while True:
    try:
        rcv_flag = False
        sent += 1
        s.sendto(str(seq).encode('utf-8'),
                 (server_addr, server_port))
        t0 = time.time()
        data, addr = s.recvfrom(512)
        t1 = time.time()
        rcv_flag = True
        rcv += 1

        interval = round((t1 - t0) * 1000, 3)
        if interval > rtt_max:
            rtt_max = interval
        if interval < rtt_min:
            rtt_min = interval
        report = report_temp % (len(data), seq, interval)
        print(report)
        seq += 1
        total_time += interval
        time.sleep(1)
    except KeyboardInterrupt:
        if rcv_flag == False:
            # 已发出包在等待响应时终止，则忽略最后一个包
            sent -= 1
        loss_rate = format(1 - (rcv / sent), '.2%')
        report = statis_temp % (sent, rcv, loss_rate, round(total_time, 2),
                                rtt_min, round(total_time / sent, 2), rtt_max)
        print(report)
        break
    except socket.timeout:
        print('seq=%d, timeout!' % seq)
        seq += 1
        continue
