-module(ip_example).

-export([main/0]).

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
  spawn(fun() -> loop_recv(Tun1) end),
  % 发送数据
  loop_send(Tun0),
  % 阻塞主进程，方便查看输出
  timer:sleep(100000).

loop_recv(Tun) ->
  Res = ip:recv(Tun),
  %%recv异步阻塞函数，解析接收到的ip数据,错误格式ip包返回nil, 正确解析分两种情况
  %%返回分片数据或者非分片返回完整的数据, 返回格式
  %% {false, ip_head(), {frag_key(), frag}}
  %% {true, ip_head(), binary()}
  io:format("recv: ~p~n", [Res]),
  loop_recv(Tun).

loop_send(Tun) ->
  loop_send(Tun, 0).

%发10个包
loop_send(_Tun, 10) ->
  ok;
loop_send(Tun, T) ->
  Config = ip:init_config([{src_ip, "192.168.5.3"}, {dst_ip, "192.168.4.2"}, {id, T}]),
  HeadRaw = ip:make_ip_head_raw(Config), %初始化IP Head
  ip:send(Tun, HeadRaw, <<T:8>>), %发送ID号
  timer:sleep(2000), %每两秒发一次
  loop_send(Tun, T + 1).
