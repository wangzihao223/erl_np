-module(udp).

-export([send/7, send/2]).
-export([make_handler/5]).

-include("ip.hrl").

-record(udp_pack,
        {source_port = 0 :: non_neg_integer(),
         destination = 0 :: non_neg_integer(),
         length = 0 :: non_neg_integer(),
         checksum = 0 :: non_neg_integer(),
         data = <<>> :: binary()}).
-record(handler,
        {id :: non_neg_integer(),
         header_raw :: ip:header_raw(),
         device :: erlang:reference(),
         source_addr :: string(),
         source_port :: non_neg_integer(),
         dest_addr :: string(),
         dest_port :: non_neg_integer()}).

-type handler() ::
  #handler{id :: non_neg_integer(),
           header_raw :: ip:header_raw(),
           device :: erlang:reference(),
           source_addr :: string(),
           source_port :: non_neg_integer(),
           dest_addr :: string(),
           dest_port :: non_neg_integer()}.
-type udp_pack() ::
  #udp_pack{source_port :: non_neg_integer(),
            destination :: non_neg_integer(),
            length :: non_neg_integer(),
            checksum :: non_neg_integer(),
            data :: binary()}.

-spec send(Handler, Data) -> NewHandler
  when Handler :: handler(),
       Data :: binary(),
       NewHandler :: handler().
send(Handler, Data) ->
  #handler{source_port = SourcePort,
           source_addr = SourceAddr,
           dest_addr = DestAddr,
           dest_port = DestPort,
           id = ID,
           header_raw = HeaderRaw,
           device = Device} =
    Handler,
  Bin = make_udp_pack(SourceAddr, SourcePort, DestAddr, DestPort, Data),

  HR1 = HeaderRaw#ip_head{identification = ID},
  ip:send(Device, HR1, Bin),
  case ID bsr 16 of
    0 ->
      Handler#handler{id = ID + 1};
    _ ->
      Handler#handler{id = 0}
  end.

-spec make_handler(Device, SourceAddr, SourcePort, DestAddr, DestPort) -> Handler
  when Device :: reference(),
       SourceAddr :: string(),
       SourcePort :: non_neg_integer(),
       DestAddr :: string(),
       DestPort :: non_neg_integer(),
       Handler :: handler().
make_handler(Device, SourceAddr, SourcePort, DestAddr, DestPort) ->
  Config = ip:init_config([{src_ip, SourceAddr}, {dst_ip, DestAddr}, {protocol, udp}]),
  HeaderRaw = ip:make_ip_head_raw(Config),

  #handler{id = 0,
           source_port = SourcePort,
           source_addr = SourceAddr,
           header_raw = HeaderRaw,
           device = Device,
           dest_addr = DestAddr,
           dest_port = DestPort}.

-spec make_udp_pack(SourceAddr, SourcePort, DestAddr, DestPort, Data) -> Pack
  when SourceAddr :: string(),
       SourcePort :: non_neg_integer(),
       DestAddr :: string(),
       DestPort :: non_neg_integer(),
       Data :: binary(),
       Pack :: binary().
make_udp_pack(SourceAddr, SourcePort, DestAddr, DestPort, Data) ->
  Length = size(Data) + 8,
  Header = <<SourcePort:16, DestPort:16, Length:16, 0:16>>,
  CheckSum = checksum(SourceAddr, DestAddr, Data, Header),
  B = <<SourcePort:16, DestPort:16, Length:16, CheckSum:16, Data/binary>>,
  B.

checksum(SourceAddr, DestAddr, Payload, Header) ->
  Source = ip:ip_to_int(SourceAddr),
  Dest = ip:ip_to_int(DestAddr),
  S = size(Payload) + 8,
  Pseudo = <<Source:32, Dest:32, 0:8, 17:8, S:16>>,
  CheckInput = <<Pseudo/binary, Header/binary, Payload/binary>>,
  checksum(CheckInput).

checksum(Check) ->
  Sum = calc_checksum(Check, 0),
  bnot Sum band 16#FFFF.

calc_checksum(<<A:8, B:8, Next/binary>>, Acc) ->
  S = A bsl 8 + B,
  S1 = deal_overflow(S + Acc),
  calc_checksum(Next, S1);
calc_checksum(<<A:8>>, Acc) ->
  S = A bsl 8,
  deal_overflow(S + Acc).

deal_overflow(S) ->
  case S bsr 16 == 0 of
    true ->
      S;
    false ->
      S1 = S band 16#FFFF + (S bsr 16),
      deal_overflow(S1)
  end.

%-type config_arg() ::
%      is_support_ecn | is_congest | has_fragment
%    | {service, best_effort | expedited_forwarding | assured_forwarding}
%    | {fragment_offset, df | mf}
%    | {protocol, tcp | udp | icmp | gre | esp | ah | ospf | stcp}
%    | {src_ip, string()}
%    | {dst_ip, string()}
%    | {ttl, non_neg_integer()}
%    | {id, non_neg_integer()}.

send(ID, Device, SourceAddr, SourcePort, DestAddr, DestPort, Data) ->
  Bin = make_udp_pack(SourceAddr, SourcePort, DestAddr, DestPort, Data),
  Config =
    ip:init_config([{src_ip, SourceAddr}, {dst_ip, DestAddr}, {protocol, udp}, {id, ID}]),
  HeaderRaw = ip:make_ip_head_raw(Config),
  ip:send(Device, HeaderRaw, Bin).
