erl_np
=====

Implementation of the Internet Protocol

## Documentation

```bash
```bash 
rebar3 exdoc
```

## Internet Protocol

实现ip包的发送和接收

### excample

1. 创建两个tun设备分别 为tun0,tun1, IP地址分别为`192.168.5.4` `192.168.4.4`

```erlang
Tun0 = tuntap:tuntap_init(), % 创建一个tun设备
%此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
tuntap:tuntap_start(Tun0, 16#0002, 257), 
tuntap:tuntap_up_nif(Tun0),
tuntap:tuntap_set_ip_nif(Tun0, "192.168.5.4", 24),

Tun1 = tuntap:tuntap_init(), % 创建一个tun设备
%此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
tuntap:tuntap_start(Tun1, 16#0002, 257), 
tuntap:tuntap_up_nif(Tun1),
tuntap:tuntap_set_ip_nif(Tun1, "192.168.4.4", 24),
```

2. 使用Tun0 发送ip包到Tun1

```erlang
%发10个包
loop_send(_Tun, 10) ->
  ok;
loop_send(Tun, T) ->
  Config = ip:init_config([{src_ip, "192.168.5.3"},
     {dst_ip, "192.168.4.2"}, {id, T}]),
  HeadRaw = ip:make_ip_head_raw(Config), %初始化IP Head
  ip:send(Tun, HeadRaw, <<T:8>>), %发送ID号
  timer:sleep(2000), %每两秒发一次
  loop_send(Tun, T + 1).
```

3. 监听tun1接收并解析数据

```erlang
loop_recv(Tun)->
    Res = ip:recv(Tun), 
    %%recv异步阻塞函数，解析接收到的ip数据,错误格式ip包返回nil, 正确解析分两种情况
    %%返回分片数据或者非分片返回完整的数据, 返回格式
    %% {false, ip_head(), {frag_key(), frag}}
    %% {true, ip_head(), binary()}
    io:format("recv: ~p~n", [Res]),
    loop_recv(Tun).
```

```erlang
main() ->
    Tun0 = tuntap:tuntap_init(), % 创建一个tun设备
    %此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
    tuntap:tuntap_start(Tun0, 16#0002, 257), 
    tuntap:tuntap_up_nif(Tun0),
    tuntap:tuntap_set_ip_nif(Tun0, "192.168.5.4", 24),

    Tun1 = tuntap:tuntap_init(), % 创建一个tun设备
    %此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
    tuntap:tuntap_start(Tun1, 16#0002, 257), 
    tuntap:tuntap_up_nif(Tun1),
    tuntap:tuntap_set_ip_nif(Tun1, "192.168.4.4", 24),
    % 创建一个进程监听tun1
    spawn(fun()->loop_recv(Tun1)end), 
    % 发送数据
    loop_send(Tun0),
    % 阻塞主进程，方便查看输出
    timer:sleep(100000).
```

运行结果
使用root权限执行程序，创建tun需要root权限

ip_head 是 包头部信息， nil是系统发送的其他不符合ip协议的包

```bash
recv: {true,{ip_head,4,6,0,1,25,0,2,0,63,6,45192,3232236803,3232236546,[],
                     <<>>},
            <<0>>}
recv: {true,{ip_head,4,6,0,1,25,1,2,0,63,6,45191,3232236803,3232236546,[],
                     <<>>},
            <<1>>}
recv: nil
recv: {true,{ip_head,4,6,0,1,25,2,2,0,63,6,45190,3232236803,3232236546,[],
                     <<>>},
            <<2>>}
recv: {true,{ip_head,4,6,0,1,25,3,2,0,63,6,45189,3232236803,3232236546,[],
                     <<>>},
            <<3>>}
recv: {true,{ip_head,4,6,0,1,25,4,2,0,63,6,45188,3232236803,3232236546,[],
                     <<>>},
            <<4>>}
recv: {true,{ip_head,4,6,0,1,25,5,2,0,63,6,45187,3232236803,3232236546,[],
                     <<>>},
            <<5>>}
recv: nil
recv: {true,{ip_head,4,6,0,1,25,6,2,0,63,6,45186,3232236803,3232236546,[],
                     <<>>},
            <<6>>}
```

## ICMP

接下来我们复杂一点，实现发送给另外主机的icmp协议的echo 包。

```erlang
-module(icmp_example).

-export([main/0]).
-export([loop_send/1]).

main() ->
  Tun0 = tuntap:tuntap_init(), % 创建一个tun设备
  %此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
  tuntap:tuntap_start(Tun0, 16#0002, 257),
  tuntap:tuntap_up_nif(Tun0),
  tuntap:tuntap_set_ip_nif(Tun0, "10.0.0.2", 24),
  Tun0.

loop_send(Tun) ->
  loop_send(Tun, 0).

%发10个包
loop_send(_Tun, 20) ->
  ok;
loop_send(Tun, T) ->
  Config =
    ip:init_config([{src_ip, "10.0.0.3"},
                    {dst_ip, "192.168.31.252"},
                    {id, T},
                    {protocol, icmp}]),
  HeadRaw = ip:make_ip_head_raw(Config), %初始化IP Head
  Data = icmp:make_echo_msg(1, T, <<"icmp">>),
  ip:send(Tun, HeadRaw, Data), %发送icmp
  io:format("send : ~p~n", [Data]),
  timer:sleep(1000), %每两秒发一次
  loop_send(Tun, T + 1).
```

运行程序 监听目标网卡



1. 首先 执行main函数开启网卡，然后`iptables` 做 **源地址伪装（SNAT）**

```bash
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

- `-s 10.0.0.0/24`：匹配从 TUN 网段出来的包

- `-o eth0`：出接口是物理网卡

- `MASQUERADE`：让包使用本机的 `192.168.31.55` 地址发出去



- 用户态构造的 IP 包（源 IP 是 10.0.0.1，目标是 192.168.31.252（另一台主机））写入 tun0；

- 内核看到包从 tun0 进来，目的是局域网 IP；

- iptables NAT 会把源 IP 改成 192.168.31.55（本机Ip）；

- 包就像是“从本机真实发出去的一样”→ 到达目标主机！
2. 我们监听一下本机：

```bash
sudo tcpdump -i eth0 -n icmp
```

3. 在另一台主机也监听一下使用相同的命令

4. 运行 loop_send

查看本机结果

```bash
cpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:22:08.818964 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 0, length 12
10:22:08.820423 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 0, length 12
10:22:09.820167 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 1, length 12
10:22:09.820936 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 1, length 12
10:22:10.821152 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 2, length 12
10:22:10.821906 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 2, length 12
10:22:11.822122 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 3, length 12
10:22:11.822981 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 3, length 12
10:22:12.823118 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 4, length 12
10:22:12.823880 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 4, length 12
```

目标主机


```bash
03:22:55.009497 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 0, length 12
03:22:55.009517 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 0, length 12
03:22:56.009902 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 1, length 12
03:22:56.009914 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 1, length 12
03:22:57.010924 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 2, length 12
03:22:57.010935 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 2, length 12
03:22:58.011909 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 3, length 12
03:22:58.011918 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 3, length 12
03:22:59.012915 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 4, length 12
03:22:59.012924 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 4, length 12
03:23:00.014159 IP 192.168.31.55 > 192.168.31.252: ICMP echo request, id 1, seq 5, length 12
03:23:00.014166 IP 192.168.31.252 > 192.168.31.55: ICMP echo reply, id 1, seq 5, length 12

```







