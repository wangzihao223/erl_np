-module(udp_example).

-export([main/0]).

main() ->
  Tun0 = tuntap:tuntap_init(), % 创建一个tun设备
  %此函数将使用模式`mode`和可选的设备单元`unit`来配置设备。
  tuntap:tuntap_start(Tun0, 16#0002, 257),
  tuntap:tuntap_up_nif(Tun0),
  tuntap:tuntap_set_ip_nif(Tun0, "10.0.0.2", 24),
  Handler = udp:make_handler(Tun0, "10.0.0.3", 8888, "192.168.31.252", 8888),

  loop_send(Handler, 0).

loop_send(_Handler, 30) ->
  ok;
loop_send(Handler, T) ->
  Handler1 = udp:send(Handler, <<"hello,world">>),
  timer:sleep(1000), %每两秒发一次
  loop_send(Handler1, T + 1).
