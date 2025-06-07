-module(icmp_example).

-export([main/0]).

make_tun(IP) ->
  Device = tuntap:tuntap_init(),
  tuntap:tuntap_start(Device, 16#0002, 257),
  tuntap:tuntap_up_nif(Device),
  tuntap:tuntap_set_ip_nif(Device, IP, 24),
  Device.

write_data(Device, Data) ->
  io:format("write_data ~p~n", [Data]),
  tuntap:tuntap_write_nif(Device, Data).

make_icmp_echo(ID, Seq, Data, Opt) ->
  Payload = icmp:make_echo_msg(ID, Seq, Data),
  Opt1 = [{total_length, 20 + size(Payload)} | Opt],
  Config = ip:init_config(Opt1),
  {Head, _} = ip:make_ip_head(Config),
  <<Head/binary, Payload/binary>>.

make_pack(Seq) ->
  Opt = [{src_ip, "192.168.4.20"}, {dst_ip, "192.168.5.30"}, {protocol, icmp}],
  make_icmp_echo(0, Seq, <<"hello">>, Opt).

main() ->
  D = make_tun("192.168.4.3"),
  D1 = make_tun("192.168.5.3"),
  spawn(fun() -> write_process1(D, 0) end),
  spawn(fun() -> read_process(D1) end),
  ok.

write_process1(D, Seq) ->
  Data = make_pack(Seq),
  write_data(D, Data),
  timer:sleep(3000),
  write_process1(D, Seq + 1).

read_process(D) ->
  Fd = tuntap:tuntap_get_fd_nif(D),
  tuntap:tuntap_wait_read_nif(D, Fd, self()),
  receive
    Notice ->
      io:format("INFO:~p~n", [Notice]),
      R = tuntap:tuntap_read_nif(D),
      io:format("read: => ~p length ~p ~n ", [R, size(R)]),
      read_process(D)
  end.
