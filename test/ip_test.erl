-module(ip_test).

-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

%% 假设你有一个函数 new_ip_package(Config, Payload)

-ifdef(EUNIT).

-define(DEBUG, true).

basic_ip_pack_test() ->
  Config = ip:init_config([{src_ip, "1.2.3.4"}, {dst_ip, "5.6.7.8"}]),
  HR = ip:make_ip_head_raw(Config),
  ?debugFmt("HR ~p~n", [HR]),
  Payload = <<"hello">>,
  [Bin] = ip:new_ip_package(HR, Payload),
  ?assert(is_binary(Bin)).

basic_unpack_test() ->
  Config = ip:init_config([{src_ip, "1.2.3.4"}, {dst_ip, "5.6.7.8"}]),
  HR = ip:make_ip_head_raw(Config),
  Payload = <<"hello">>,
  [Bin] = ip:new_ip_package(HR, Payload),
  Res = ip:unpack_ip_head(Bin),
  ?debugFmt("Res ~p~n", [Res]).

make_option_test() ->
  O1 = ip:new_option(1, 0, 12, <<"helloworldzz">>),
  O2 = ip:new_option(0, 0, 13, <<"wangzihao">>),
  Config = ip:init_config([{src_ip, "1.2.3.4"}, {dst_ip, "5.6.7.8"}, {option, [O1, O2]}]),

  HR = ip:make_ip_head_raw(Config),
  %?debugFmt("HR ~p~n", [HR]),
  BinList = ip:new_ip_package(HR, <<10:(3000 * 8)>>),
  %?debugFmt("HR ~p~n", [BinList]),
  Buffer = loop(BinList, []),
  _Data = ip:reassemble_frags(Buffer),
  ok.

  %?debugFmt("data ~p~n", [Data]).

loop([], Acc) ->
  Acc;
loop([Bin | Next], Acc) ->
  %?debugFmt("Bin~p~n", [Bin]),
  {_, Header, {_FragKey, Frag}} = ip:unpack_ip_head(Bin),
  %?debugFmt("Header ~p~n", [Header]),
  Acc1 = ip:insert_fragment_buffer(Acc, Frag),
  loop(Next, Acc1).

my_test_() ->
  {timeout, 100, [fun test_send/0]}.

test_send() ->
  Device = tuntap:tuntap_init(),
  IP = "192.168.5.4",
  tuntap:tuntap_start(Device, 16#0002, 257),
  tuntap:tuntap_up_nif(Device),
  tuntap:tuntap_set_ip_nif(Device, IP, 24),

  Device2 = tuntap:tuntap_init(),
  IP1 = "192.168.4.4",
  tuntap:tuntap_start(Device2, 16#0002, 257),
  tuntap:tuntap_up_nif(Device2),
  tuntap:tuntap_set_ip_nif(Device2, IP1, 24),

  spawn(fun() -> recv(Device2) end),
  loop_send(Device, 0),
  timer:sleep(10000).

loop_send(_D, 100) ->
  ok;
loop_send(Device, T) ->
  O1 = ip:new_option(1, 0, 12, <<"helloworldzz">>),
  O2 = ip:new_option(0, 0, 13, <<"wangzihao">>),
  Config =
    ip:init_config([{src_ip, "192.168.5.3"},
                    {dst_ip, "192.168.4.2"},
                    {option, [O1, O2]},
                    {id, T}]),

  HR = ip:make_ip_head_raw(Config),
  ip:send(Device, HR, <<T:(10 * 8)>>),
  ?debugFmt("send ok HR ~p", [HR]),
  timer:sleep(2000),
  loop_send(Device, T + 1).

recv(Device) ->
  Res = ip:recv(Device),
  ?debugFmt("Recv ~p~n", [Res]),
  recv(Device).

-endif.
