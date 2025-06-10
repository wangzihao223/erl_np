-module(ip).


-moduledoc """
INTERNET PROTOCOL

本模块提供以下功能

  - 构建IP数据包，包括IPv4报文头各个字段填充.

  - 解析 IP 数据包，提取报文头及其负载。

  - 支持 IP 分片机制，将超出 MTU 的报文分片传输。

  - 支持 IP 重组机制，将多个分片还原为完整报文。


本模块遵循 RFC 791 的 IPv4 协议规范。
适用于需要用户态处理 IP 层报文的系统。
""".

-define(DEFAULT, 0).
-define(EF, 46).
-define(AF11, 10).
-define(AF21, 10).
-define(AF31, 18).
-define(TTL, 64).
-define(MTU, 1500).

-export([init_config/1, new_ip_package/2, make_ip_head_raw/1]).
-export([insert_fragment_buffer/2, check_complete/1, reassemble_frags/1]).
-export([unpack_ip_head/1]).

-export([send/11, send/3]).
-export([recv/1 ]).
-export([new_option/4 ]).

-ifdef(TEST).
-export([get_option_type/2 ]).
-export([make_options/3 ]).
-endif.

-record(ip_head,
        {version = 4,
         ihl = 0,
         dscp = ?DEFAULT,
         ecn = 2,
         total_length = 0,
         identification = 0,
         flags = 2,
         fragment_offset = 0,
         time_to_live = ?TTL,
         protocol = tcp,
         header_checksum = 0,
         source_addr = 0,
         destination_addr = 0,
         option = [],
         padding = <<>>}).

-type ip_head() :: #ip_head{
    version          :: 4,
    ihl              :: non_neg_integer(),
    dscp             :: non_neg_integer(),
    ecn              :: 0..3,
    total_length     :: non_neg_integer(),
    identification   :: non_neg_integer() | nil,
    flags            :: non_neg_integer() | nil,
    fragment_offset  :: non_neg_integer() | nil,
    time_to_live     :: non_neg_integer() | nil,
    protocol         :: non_neg_integer() | nil,
    header_checksum  :: non_neg_integer() | nil,
    source_addr      :: non_neg_integer() | nil,
    destination_addr :: non_neg_integer()| nil,
    option           :: list(head_option()) | nil,
    padding          :: binary() | nil
}.

-record(head_option,
        {copied_flag = 0,
         option_class = 0,
         option_num = 0,
         option_type = 0,
         option_length = nil,
         option_pyaload = <<>>}).

-type head_option() :: #head_option{
                          copied_flag :: non_neg_integer(),
                          option_class :: non_neg_integer(),
                          option_num :: non_neg_integer(),
                          option_type :: non_neg_integer(),
                          option_length :: non_neg_integer(),
                          option_pyaload :: binary()
                         }.


%% doc 表示一个 IP 分片的数据结构，用于在分片重组过程中存储分片信息。

-record(frag, {
    offset,   %% 分片偏移量，单位为 8 字节（对应 IPv4 Fragment Offset 字段）
    mf,       %% More Fragments 标志，类型为 boolean()，true 表示还有更多分片
    payload   %% 分片所携带的有效数据（二进制）
}).

%%frag 类型别名，用于类型推导和文档生成。

-type frag() :: #frag{
    offset  :: non_neg_integer(),
    mf      :: boolean(),
    payload :: binary()
}.

%%  唯一标识一个 IP 分片包的键（四元组）。
%% 用于在分片重组过程中进行定位和区分。

-record(frag_key, {
    src_ip,     %% 源 IP 地址，类型为 int
    dst_ip,     %% 目标 IP 地址，类型为 int TODO: 是否化为 inet:ip_address()
    id,         %% IP 标识字段（16 位整数）
    protocol    %% 协议号（如 6=TCP, 17=UDP）rfc790
}).
-doc """
frag_key() 用于 IP 分片重组标识
    - src_ip   :: non_neg_integer() source ip address
    - dst_ip   :: non_neg_integer() destination ip address
    - id       :: integer() identification number 16 bits
    - protocol :: integer() protocol number , please read rfc790
""".

%%  类型别名：frag_key() 用于 IP 分片重组标识。
-type frag_key() :: #frag_key{
    src_ip   :: non_neg_integer(), %% source ip address
    dst_ip   :: non_neg_integer(), %% Destination ip address
    id       :: integer(),         %% identification number 16 bits
    protocol :: integer()          %% protocol number , please read rfc790
}.

-doc """
Represents one configuration argument used to construct an IP config map.
用于构建config()的一个配置参数
This type is a union of simple atom flags (e.g., `is_support_ecn`) and
key-value tuples (e.g., `{service, best_effort}`).

Used as input to configuration functions such as `init_config/1`.
""".
-type config_arg() ::
      is_support_ecn | is_congest | has_fragment
    | {service, best_effort | expedited_forwarding | assured_forwarding}
    | {fragment_offset, df | mf}
    | {protocol, tcp | udp | icmp | gre | esp | ah | ospf | stcp}
    | {src_ip, string()}
    | {dst_ip, string()}
    | {ttl, non_neg_integer()}
    | {id, non_neg_integer()}.

-type config() :: #{
    service := best_effort | expedited_forwarding | assured_forwarding,
    is_support_ecn := boolean(),
    is_congest := boolean(),
    has_fragment := boolean(),
    fragment_offset := df | mf,
    protocol := tcp | udp | icmp | gre | esp | ah | ospf | stcp,
    src_ip := string(),
    dst_ip := string(),
    ttl := non_neg_integer(),
    id := non_neg_integer()
}.


-spec send(
  Device :: reference(),
  SrcIp :: string(), DstIp :: string(), Proto :: atom(),
  TOS :: atom(), TTL :: integer(),
  Payload :: binary(), Len :: integer(), Id :: integer(),
  DF :: boolean(), Opt :: list()
) -> ok | {error, term()}.

send(Device, Src, Dst, Proto, TOS, TTL, Buf, _Len, Id, DF, Opt) ->
    Config = init_config([
      {src_ip, Src},
      {dst_ip, Dst},
      {protocol, Proto},
      {service, TOS},
      {id, Id},
      {ttl, TTL},
      is_support_ecn,
      {fragment_offset, if DF -> df; true -> mf end},
      {option, Opt}
    ]),
    Packets = new_ip_package(Config, Buf),
    %% send via TUN or socket etc.
    write_to_device(Device, Packets).


-spec send(Device,HeaderRaw,Payload) -> Length when
    Device :: reference(),
    HeaderRaw :: ip_head(),
    Payload :: binary(),
    Length :: non_neg_integer().

send(Device, HeaderRaw, Payload) ->
  Packets = new_ip_package(HeaderRaw, Payload),
  write_to_device(Device, Packets).

%BufPTR = buffer pointer
%prot = protocol
%result = response
%OK = datagram received ok
%Error = error in arguments
%len = length of buffer
%src = source address
%dst = destination address
%TOS = type of service
%opt = option da
%
-doc"""
Receive tun data and parse ip protocol package
""".
-spec recv(Device::reference()) -> { boolean( ) , ip_head() , binary( ) | { frag_key() , frag() } }.
recv(Device) ->
  Fd = tuntap:tuntap_get_fd_nif(Device),
  tuntap:tuntap_wait_read_nif(Device, Fd, self()),
  receive
    {select, Obj, Ref, ready_input}->
      {Obj, Ref},
      Pack = tuntap:tuntap_read_nif(Device),
      unpack_ip_head(Pack)
      %Pack
  end.

-doc """
 Configuration options used for building IP packets.

 The config map contains settings related to fragmentation,  and protocol.

 - `service`:
   dscp 的主要用途是区分网络中不同种类的流量，实现差异化服务，比如优先转发语音、视频，降低延迟等。
   Specifies the Differentiated Services (DiffServ) level. 
   One of:
   - `best_effort`
   - `expedited_forwarding`
   - `assured_forwarding`

 - `is_support_ecn`:
   是否支持“显式拥塞通知”
   Whether Explicit Congestion Notification (ECN) is supported.
   
 - `is_congest`:
    是否拥塞
   Whether the sender is in a congestion state.

 - `has_fragment`:
   是否分片
   Indicates if the IP packet is fragmented.

 - `fragment_offset`:
   分片偏移量
   Fragmentation flag, either:
   - `df`: Don't Fragment
   - `mf`: More Fragments

 - `protocol`:
   Upper layer protocol number:
   协议
   - `tcp`
   - `udp`
   - `icmp`
   - `gre`
   - `esp`
   - `ah`
   - `ospf`
   - `stcp`

 - `src_ip`:
   Source IP address as string (e.g., `"192.168.0.1"`).

 - `dst_ip`:
   Destination IP address as string.

 - `id`:
   IP identifier used for fragmentation and reassembly
""".

-spec init_config([Args]) -> Config when
    Args :: [config_arg()],
    Config :: config().

init_config(Args) ->
  Config = init_config_1(),
  Opts =
    lists:map(fun ({K, V}) ->
                    {K, V};
                  (K) when is_atom(K) ->
                    {K, true}
              end,
              Args),
  {_, Config1} =
    lists:mapfoldl(fun({K, V}, Conf) ->
                      case maps:is_key(K, Conf) of
                        true -> {{K, V}, Conf#{K => V}};
                        false -> error({bad_arg, "bad argument"})
                      end
                   end,
                   Config,
                   Opts),
  Config1.

init_config_1() ->
  Config =
    #{service => best_effort,
      is_support_ecn => true,
      is_congest => false,
      fragment_flag => df,
      has_fragment => false,
      fragment_offset => 0,
      protocol => tcp,
      src_ip => "192.168.0.1",
      dst_ip => "8.8.8.8",
      option => [],
      ttl => ?TTL,
      id => 0},
  Config.

-doc """
 Constructs a raw IP header record (`ip_head()`) from a given config map.


This function extracts necessary fields from the provided `Config` map,
including service type, ECN flags, source/destination IPs, protocol, and more.
It converts these into a structured `#ip_head{}` record that can be further used
to encode or manipulate IP packets.

""".
-spec make_ip_head_raw(Config) -> HeaderRaw when
    Config :: config(),
    HeaderRaw :: ip_head().
make_ip_head_raw(Config) ->
  Service = map_get(service, Config),
  SupportECN = map_get(is_support_ecn, Config),
  IsCongest = map_get(is_congest, Config),
  Protocol = map_get(protocol, Config),
  SrcIP = ip_to_int(map_get(src_ip, Config)),
  DstIP = ip_to_int(map_get(dst_ip, Config)),
  T2L = map_get(ttl, Config),
  Option =
    case map_get(option, Config) of
      nil ->
        [];
      Opt ->
        Opt
    end,
  ID = map_get(id, Config),

  Dscp = service_to_dscp(Service),
  Ecn = make_ecn(SupportECN, IsCongest),
  ProtocolNumber = protocol_number(Protocol),

  HeaderRaw =
    #ip_head{dscp = Dscp,
             ecn = Ecn,
             identification = ID,
             time_to_live = T2L,
             protocol = ProtocolNumber,
             source_addr = SrcIP,
             destination_addr = DstIP,
             option = Option},
  HeaderRaw.

-doc """
make a ip package , Constructs a complete IP packet or a list of fragments if the payload exceeds the MTU.


Arguments:
  - `HeaderRaw`: IP header record (ip_head())
  - `Payload`: binary data 

Returns:
  - A list of binary-encoded IP packets

_Example:_
```erlang
1> new_ip_package(Header, <<"Hello">>).
[<<...>>]
""".
-spec new_ip_package(HeaderRaw, Payload) -> Package when HeaderRaw :: ip_head(),
                                                         Payload :: binary(),
                                                         Package :: [binary()].
new_ip_package(HeaderRaw, Payload) ->
  L = get_header_length(HeaderRaw, #{}),
  if size(Payload) + L =< ?MTU ->
       % don't need fragment
       HeaderRaw1 = HeaderRaw#ip_head{flags = 2, fragment_offset = 0},
       {HeaderBin, _HeaderRaw} = ip_package_creater(HeaderRaw1, Payload, #{}),
       [HeaderBin];
     true ->
       % need fragment
       HeaderRaw1 = HeaderRaw#ip_head{flags = 1, fragment_offset = 0},
       MaxPayloadSize = (?MTU - L) band bnot 7,
       <<Payload1:MaxPayloadSize/bytes, Reamin/binary>> = Payload,
       {First, HeaderRaw2} = ip_package_creater(HeaderRaw1, Payload1, #{}),
       fragment(HeaderRaw2, Reamin, MaxPayloadSize div 8, [First])
  end.


-doc """
Parses a raw IP packet and returns either the complete payload or information
required for fragment reassembly.

解析原始 IP 数据包，并返回完整载荷，或用于 IP 分片重组所需的信息。

### return

Returns a 3-tuple `{IsFrag, IPHead, Data}`:

- `IsFrag` :: `boolean()`  
  
  是否为分片包：  
  - `false` 表示此包为完整的 IP 数据包  
  - `true` 表示此包为 IP 分片（需要重组）

- `IPHead` :: `#ip_head{}`  
  已解析的 IP 头部结构体

- `Data` ::  
  - `Payload :: binary()` — 当 `IsFrag = false`，为完整 IP 包的有效载荷  
  - `{FragKey, Frag}` — 当 `IsFrag = true`，为以下内容：  
    - `FragKey :: frag_key()` — 用于唯一标识一个 IP 包（例如包含 源 IP、目标 IP、ID、协议）  
    - `Frag :: frag()` — 当前分片信息（偏移、是否最后一片、数据等）

### example

```erlang
{false, IPHead, Payload} = unpack_ip_head(RawBin),
% or
{true, IPHead, {FragKey, Frag}} = unpack_ip_head(AnotherBin).
""".
-spec unpack_ip_head( binary( ) ) -> { boolean( ) , #ip_head{ } , binary( ) | { frag_key() , frag() } } | nil.
unpack_ip_head(<<>>) -> nil;

unpack_ip_head(<<V:4,_:4,_/binary>>) when V =/= 4 -> nil;

unpack_ip_head(Pack) ->

  <<_:4, IHL:4, _/binary>> = Pack,
  L = IHL * 4,

  <<Head:L/bytes, Payload/binary>> = Pack,
  <<V:4,
    IHL:4,
    Dscp:6,
    Ecn:2,
    TL:16,
    ID:16,
    Flags:3,
    FragmentOffset:13,
    T2L:8,
    Protocol:8,
    HeadCheckSum:16,
    SrcAddr:32,
    DestAddr:32,
    Options/binary>> =
    Head,
  OptionList = get_option_type(Options, []),
  HeaderRaw =
    #ip_head{ihl = IHL,
             dscp = Dscp,
             ecn = Ecn,
             total_length = TL,
             identification = ID,
             flags = Flags,
             fragment_offset = FragmentOffset,
             time_to_live = T2L,
             protocol = Protocol,
             header_checksum = HeadCheckSum,
             source_addr = SrcAddr,
             destination_addr = DestAddr,
             option = OptionList},
  PayloadSize = TL - IHL * 4,

  <<Payload1:PayloadSize/bytes, _/binary>> = Payload,
  if Flags == 2 ->
       %完整的包
       {true, HeaderRaw, Payload1};
     true ->
       FragKey = new_frag_key(SrcAddr, DestAddr, ID, Protocol),
       Frag = new_frag(FragmentOffset, Flags, Payload1),
       {false, HeaderRaw, {FragKey, Frag}}
  end.

-doc """

Inserts a fragment into a sorted fragment buffer, maintaining order by offset.

this function uses the _difference list_ technique to insert a new fragment
(`frag()`) into a buffer (a list of `frag()`) ordered by their `offset` field.
This avoids costly list reversal and preserves performance even for long lists.

## Parameters

  - `Buffer`: A list of `frag()` elements, sorted by `frag#frag.offset`.
  - `Frag`: A new `frag()` to insert.

## Returns

  - A new list of `frag()` with `Frag` inserted at the correct position.

## Example

```erlang
1> insert_fragment_buffer([#frag{offset=0}], #frag{offset=1}).
[#frag{offset=0}, #frag{offset=1}]

""".
-spec insert_fragment_buffer(Buffer, Frag) -> NewBuffer when
    Buffer :: [frag()],
    Frag ::frag(),
    NewBuffer :: [frag()].
insert_fragment_buffer(Buffer, Frag) ->
  DF = insert_fragment_buffer(fun(Tail)-> Tail end, Buffer, Frag),
  DF([]).

-doc """
Insert into the buffer in order
""".
-spec insert_fragment_buffer(DLAcc, Buff, Frag) -> NewBuffer when
    DLAcc :: fun((Tail::[Frag]) -> [frag()]),
    Buff :: [frag()],
    Frag :: frag(),
    NewBuffer ::[frag()].

insert_fragment_buffer(L, [], Frag) ->
  fun(Tail) -> L([Frag|Tail])end;
insert_fragment_buffer(L, [Head | Next], Frag) ->
  HeadOffset = Head#frag.offset,
  Offset = Frag#frag.offset,
  case Offset < HeadOffset of
    true ->
      DL = fold_to_diff(Next),
      fun(Tail)-> L([Frag, Head | DL(Tail)]) end;
    false ->
      L1 = fun(Tail) -> L([Head|Tail]) end,
      insert_fragment_buffer(L1, Next, Frag)
  end.

-doc """
Checks whether a fragment buffer contains a complete IP datagram.

This function verifies whether all IP fragments in `Buffer` are:
1. **Contiguous** — i.e., there are no gaps in the offsets.
2. **Complete** — i.e., the final fragment has the `mf` (More Fragments) flag set to 0.

It assumes the buffer is sorted by `frag#frag.offset` in ascending order.

## Parameters
  - `Buffer`: A list of `frag()` structures representing ordered IP fragments.

## Returns
  - `true` if the fragments are contiguous and complete.
  - `false` otherwise.

## Example

```erlang
1> check_complete([#frag{offset=0, payload=<<"abc">>, mf=1},
                   #frag{offset=3, payload=<<"def">>, mf=0}]).
true.

2> check_complete([#frag{offset=0, payload=<<"abc">>, mf=1},
                   #frag{offset=4, payload=<<"def">>, mf=0}]).
false.  % gap at offset=3

3> check_complete([]).
false.
""".
-spec check_complete(Buffer) -> IsComplete when 
    Buffer :: [frag()],
    IsComplete :: boolean().
check_complete(Buffer) ->
  check_complete(Buffer, 0).

-spec check_complete(Buffer, Offset) -> IsComplete when
    Buffer ::[frag()],
    Offset :: non_neg_integer(),
    IsComplete :: boolean().
check_complete([], _Offset) ->
  false;
check_complete([Frag], Offset) ->
  Offset1 = Frag#frag.offset,
  MF = Frag#frag.mf,
  if (Offset == Offset1) and (MF == 0) ->
       % offset
       true;
     true ->
       false
  end;
check_complete([Frag | Next], Offset) ->
  Offset1 = Frag#frag.offset,
  if Offset == Offset1 ->
       Offset2 = size(Frag#frag.payload) + Offset1,
       check_complete(Next, Offset2);
     true ->
       false
  end.

-doc """
Reassembles a list of IP fragments into a single binary payload.

This function concatenates the payload of each fragment in order,
building up the complete IP packet payload.

## Parameters
  - `Buffer`: A list of `frag()` records sorted by offset.
  - `Acc`: An accumulator binary to append fragments to, typically `<<>>`.

## Returns
  - A binary representing the reassembled payload.

## Example
```erlang
1> reassemble_frags([#frag{payload=<<"abc">>}, #frag{payload=<<"def">>}], <<>>).
<<"abcdef">>
""".
-spec reassemble_frags([frag()]) -> binary().
reassemble_frags(Buffer) ->
    reassemble_frags(Buffer, <<>>).

-spec reassemble_frags(Buffer, Acc) -> Payload when
    Buffer :: [frag()],
    Acc :: binary(),
    Payload :: binary().
reassemble_frags([], Acc) ->
  Acc;
reassemble_frags([Frag | Next], Acc) ->
  Payload = Frag#frag.payload,
  reassemble_frags(Next, <<Acc/binary, Payload/binary>>).

new_frag_key(SrcIp, DstIP, ID, Protocol) ->
  #frag_key{src_ip = SrcIp,
            dst_ip = DstIP,
            id = ID,
            protocol = Protocol}.

new_frag(Offset, Flags, Payload) ->
  #frag{offset = Offset,
        mf = Flags,
        payload = Payload}.

%-record(head_option,
%        {copied_flag = 0,
%         option_class = 0,
%         option_num = 0,
%         option_type = 0,
%         option_length = nil,
%         option_pyaload = <<>>}).
-spec new_option(CopyFlag, ClassNum, OptionNum, Payload) -> Option when
    CopyFlag :: non_neg_integer(),
    ClassNum :: non_neg_integer(),
    OptionNum :: non_neg_integer(),
    Payload :: binary(),
    Option :: head_option().

         % end_option_list ->
         %   <<0:8>>;
         % no_operation ->
         %   <<1:8>>;
new_option(CopyFlag, ClassNum, OptionNum, Payload) ->
  Opt = #head_option{copied_flag = CopyFlag,
                     option_class = ClassNum,
                     option_num = OptionNum,
                     option_pyaload = Payload
                    },
  L = case stand_options(ClassNum, OptionNum) of
    end_option_list -> 
      1;
    no_operation ->
      1;
    _ -> size(Payload) + 2
  end,
  Opt#head_option{option_length = L}.

make_ecn(SupportFlag, IsCongest) ->
  case {SupportFlag, IsCongest} of
    {false, _} ->
      % 不支持 ECN，返回 Not-ECT (0)
      0;
    {true, true} ->
      % 支持 ECN 且拥塞，返回 CE (3)
      3;
    {true, false} ->
      % 支持 ECN 且不拥塞，返回 ECT(1) (1)
      1
  end.

% 根据用途选择dscp
service_to_dscp(best_effort) ->
  0;  % 默认
service_to_dscp(expedited_forwarding) ->
  46;  % EF PHB
service_to_dscp(assured_forwarding) ->
  10;   % AF11 示例
service_to_dscp(_Other) ->
  0.

%get_flag(df, _) ->
%  2;
%get_flag(mf, true) ->
%  1;
%get_flag(mf, false) ->
%  0;
%get_flag(_, _) ->
%  erlang:error({bad_flag_argument, "invalid flag or value"}).

protocol_number(icmp) ->
  1;
protocol_number(tcp) ->
  6;
protocol_number(udp) ->
  17;
protocol_number(gre) ->
  47;
protocol_number(esp) ->
  50;
protocol_number(ah) ->
  51;
protocol_number(ospf) ->
  89;
protocol_number(sctp) ->
  132;
protocol_number(_) ->
  erlang:error(bad_protocol).

get_option_type(<<>>, OptionList) ->
  OptionList;
get_option_type(Data, OptionList) ->
  <<Type:8, R/binary>> = Data,

  <<CopiedFlag:1, OptionClass:2, OptionNum:5>> = <<Type:8>>,

  OptionType = stand_options(OptionClass, OptionNum),
  Opt =
    #head_option{copied_flag = CopiedFlag,
                 option_class = OptionClass,
                 option_num = OptionNum,
                 option_type = OptionType,
                 option_pyaload = <<>>},
  {R1, NewOpt} =
    case OptionType of
      end_option_list ->
        {<<>>, nil};
      no_operation ->
        {R, nil};
      _ ->
        {OptionPyload, Reamin} = read_option_data(R),
        Opt1 =
          Opt#head_option{option_pyaload = OptionPyload, option_length = size(OptionPyload) + 2},
        {Reamin, Opt1}
    end,
  case NewOpt of
    nil ->
      get_option_type(R1, OptionList);
    _ ->
      get_option_type(R1, [NewOpt | OptionList])
  end.

read_option_data(Data) ->
  <<L:8, R/binary>> = Data,
  L1 = L - 2,
  <<Payload:L1/bytes, Reamin/binary>> = R,
  {Payload, Reamin}.

stand_options(0, 0) ->
  end_option_list;
stand_options(0, 1) ->
  no_operation;
stand_options(0, 2) ->
  security;
stand_options(0, 3) ->
  loose_source_route;
stand_options(0, 9) ->
  strict_source_routing;
stand_options(0, 7) ->
  record_route;
stand_options(0, 8) ->
  stream_id;
stand_options(2, 4) ->
  internet_timestamp;
stand_options(_Class, _Num) ->
  other.

fragment(HeaderRaw, Payload, Offset, Acc) ->
  % frist Calculate header length
  L = get_header_length(HeaderRaw, #{check_copied => true}),
  if size(Payload) + L =< ?MTU ->
       % last fragment
       HeaderRaw1 = HeaderRaw#ip_head{flags = 0, fragment_offset = Offset},
       {HeaderBin, _HeaderRaw2} =
         ip_package_creater(HeaderRaw1, Payload, #{check_copied => true}),
       lists:reverse([HeaderBin | Acc]);
     true ->
       HeaderRaw1 = HeaderRaw#ip_head{flags = 1, fragment_offset = Offset},
       % not last
       MaxPayloadSize = (?MTU - L) band bnot 7,
       <<Payload1:MaxPayloadSize/bytes, Reamin/binary>> = Payload,
       {Header2, HeaderRaw2} = ip_package_creater(HeaderRaw1, Payload1, #{check_copied => true}),
       fragment(HeaderRaw2, Reamin, Offset + (MaxPayloadSize div 8), [Header2 | Acc])

  end.

make_options([], Acc, _Args) ->
  <<Acc/binary, 0:8>>;
make_options([Option | Next], Acc, Args) ->
  F = maps:get(check_copied, Args, false),

  #head_option{copied_flag = CopyFlag,
               option_class = OptionClass,
               option_num = OptionNum,
               option_type = OptionType,
               option_length = OptionLength,
               option_pyaload = OptionPyload} =
    Option,

  OtpBin =
    case F of
      true ->
        case CopyFlag of
          1 ->
            % should copy
            <<CopyFlag:1, OptionClass:2, OptionNum:5, OptionLength:8, OptionPyload/binary>>;
          0 ->
            skip
        end;
      false ->
        case OptionType of
          end_option_list ->
            <<0:8>>;
          no_operation ->
            <<1:8>>;
          _ ->
            <<CopyFlag:1, OptionClass:2, OptionNum:5, OptionLength:8, OptionPyload/binary>>
        end
    end,

  case OtpBin of
    skip ->
      make_options(Next, Acc, Args);
    _ ->
      make_options(Next, <<Acc/binary, OtpBin/binary>>, Args)
  end.

ip_package_creater(Header, Payload, Args) ->
  #ip_head{version = Version,
           dscp = Dscp,
           ecn = Ecn,
           identification = Identification,
           flags = Flags,
           fragment_offset = FragmentOffset,
           time_to_live = TimeToLive,
           protocol = Protocol,
           source_addr = SourceAddr,
           destination_addr = DestinationAddr,
           option = Options} =
    Header,
  Opt = make_options(Options, <<>>, Args),
  % Completion header , padding zero
  Opt1 = padding_for_option(Opt),
  IHL = (20 + size(Opt1)) div 4,
  Size = size(Payload),
  TotalLength = 20 + size(Opt1) + Size,
  HeadBin =
    <<Version:4,
      IHL:4,
      Dscp:6,
      Ecn:2,
      TotalLength:16,
      Identification:16,
      Flags:3,
      FragmentOffset:13,
      TimeToLive:8,
      Protocol:8,
      0:16,
      SourceAddr:32,
      DestinationAddr:32,
      Opt1/binary>>,
  Checksum = ip_header_checksum(HeadBin),
  P1 = binary:part(HeadBin, 0, 10),
  <<P1:(size(P1))/binary, _:16, P2/binary>> = HeadBin,
  HeaderBin1 = <<P1/binary, Checksum:16, P2/binary>>,

  Header1 = Header#ip_head{total_length = TotalLength, ihl = IHL, header_checksum = Checksum},
  {<<HeaderBin1/binary, Payload/binary>>, Header1}.

padding_for_option(Opt) ->
  ZeroCount = (4 - (size(Opt) rem 4)) rem 4,

  <<Opt/binary, 1:(ZeroCount*8)>>.

get_header_length(Header, Args) ->
  Options = Header#ip_head.option,
  OptBin = make_options(Options, <<>>, Args),
  20 + size(OptBin).

-spec ip_header_checksum(binary()) -> integer().
ip_header_checksum(Header) ->
  %% 校验和字段（第11、12字节）应置0后计算
  ZeroedHeader = zero_checksum_field(Header),
  Words = binary_to_words(ZeroedHeader),
  Sum = sum_words(Words),
  Checksum = ones_complement(Sum),
  Checksum.

%% 将校验和字段置为0（第11、12字节，偏移10-11）
-spec zero_checksum_field(binary()) -> binary().
zero_checksum_field(Header) ->
  <<Before:80/bits, _Checksum:16, After/binary>> = Header,
  <<Before:80/bits, 0:16, After/binary>>.

%% 把二进制按16位分割成整数列表
-spec binary_to_words(binary()) -> [integer()].
binary_to_words(Bin) ->
  binary_to_words(Bin, []).

binary_to_words(<<>>, Acc) ->
  lists:reverse(Acc);
binary_to_words(<<Word:16, Rest/binary>>, Acc) ->
  binary_to_words(Rest, [Word | Acc]).

%% 对所有16位字求和，若超过16位要进位相加（模拟16位溢出）
-spec sum_words([integer()]) -> integer().
sum_words(Words) ->
  Sum = lists:foldl(fun(X, Acc) -> Acc + X end, 0, Words),
  fold_carry(Sum).

fold_carry(Sum) when Sum > 16#FFFF ->
  %% 把高16位加回低16位（进位折叠）
  fold_carry(Sum band 16#FFFF + (Sum bsr 16));
fold_carry(Sum) ->
  Sum.

%% 求1的补码：按位取反（16位）
-spec ones_complement(integer()) -> integer().
ones_complement(Value) ->
  bnot Value band 16#FFFF.

ip_to_int(IpStr) ->
  {ok, {A, B, C, D}} = inet:parse_address(IpStr),
  A bsl 24 bor (B bsl 16) bor (C bsl 8) bor D.

%different lists
% lists to  different lists
fold_to_diff(List) ->
    lists:foldr(fun(Elem, AccFun) ->
                    _AccFun1 = fun(Tail) -> [Elem | AccFun(Tail)] end
                end, 
                _AccFun = fun(Tail) -> Tail end, 
                List).


-spec write_to_device(Device, Packets) -> Length when
    Device :: reference(),
    Packets :: [binary()],
    Length :: non_neg_integer().

write_to_device(Device, Packets)->
  write_to_device(Device, Packets, 0).

write_to_device(_Device, [], Acc) -> Acc;
write_to_device(Device, [Packet|Next], Acc) -> 
  Acc1 = case tuntap:tuntap_write_nif(Device, Packet) of
    {false, _Length} -> error({write_error, nil});
    false  -> error({write_error, "device error"});
    {true, L} -> Acc+L
  end,
  write_to_device(Device, Next, Acc1).


