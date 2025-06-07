-module(icmp).

-ifdef(TEST).

-export([calc_checksum/2, make_echo_msg/4, get_type/1]).

-endif.

-export([make_echo_msg/3, make_echo_reply_msg/3, unpack_echo_msg/1]).

get_type(dest_unreachable) ->
  3;
get_type(source_quench) ->
  4;
get_type(redirect) ->
  5;
get_type(echo) ->
  8;
get_type(echo_reply) ->
  0;
get_type(time_exceeded) ->
  11;
get_type(parameter_problem) ->
  12;
get_type(time_stamp) ->
  13;
get_type(time_stamp_reply) ->
  14;
get_type(info_req) ->
  15;
get_type(info_req_reply) ->
  16.

make_echo_msg(ID, Seq, Data) ->
  Type = get_type(echo),
  make_echo_msg(Type, ID, Seq, Data).

unpack_echo_msg(Data) ->
  <<Type:8, Code:8, CheckSum:16, ID:16, Seq:16, Data1/binary>> = Data,
  #{type => Type,
    code => Code,
    checksum => CheckSum,
    id => ID,
    seq => Seq,
    data => Data1}.

make_echo_reply_msg(ID, Seq, Data) ->
  Type = get_type(echo_reply),
  make_echo_msg(Type, ID, Seq, Data).

make_echo_msg(Type, ID, Seq, Data) ->
  Msg1 = <<Type:8, 0:8, 0:16, ID:16, Seq:16, Data/binary>>,
  CheckSum = calc_checksum(Msg1, 0),
  <<Part1:16, _:16, Part2/binary>> = Msg1,
  <<Part1:16, CheckSum:16, Part2/binary>>.

calc_checksum(<<A:8, B:8, Rest/binary>>, Sum) ->
  Word = A bsl 8 + B,
  NewSum = (Sum + Word) band 16#FFFF + (Sum + Word bsr 16),
  calc_checksum(Rest, NewSum);
calc_checksum(<<A:8>>,
              Sum) ->  % 奇数字节补零
  Word = A bsl 8,
  FinalSum = (Sum + Word) band 16#FFFF + (Sum + Word bsr 16),
  bnot FinalSum band 16#FFFF;
calc_checksum(<<>>, Sum) ->
  bnot Sum band 16#FFFF.
