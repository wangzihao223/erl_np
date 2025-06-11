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
