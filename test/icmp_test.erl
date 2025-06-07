-module(icmp_test).

-include_lib("eunit/include/eunit.hrl").

%% 假设 icmp 模块已经编译好
%% 测试 make_echo_msg 构造结果是否合理
make_echo_msg_test() ->
  ID = 1234,
  Seq = 1,
  Data = <<"pingtest">>,
  Packet = icmp:make_echo_msg(ID, Seq, Data),

  %% 解析回结构体，检查 Type、Code、Checksum、ID、Seq
  <<Type:8, Code:8, CheckSum:16, RcvID:16, RcvSeq:16, RcvData/binary>> = Packet,

  ?assertEqual(8, Type),                 %% echo 请求
  ?assertEqual(0, Code),
  ?assertEqual(ID, RcvID),
  ?assertEqual(Seq, RcvSeq),
  ?assertEqual(Data, RcvData),

  %% 校验和也做一次验证（应该为 0 表示校验通过）
  ?assertEqual(0, icmp:calc_checksum(Packet, 0)).
