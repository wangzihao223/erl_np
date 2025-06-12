-define(DEFAULT, 0).
-define(EF, 46).
-define(AF11, 10).
-define(AF21, 10).
-define(AF31, 18).
-define(TTL, 64).
-define(MTU, 1500).

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
-record(head_option,
        {copied_flag = 0,
         option_class = 0,
         option_num = 0,
         option_type = 0,
         option_length = nil,
         option_pyaload = <<>>}).
-record(frag,
        {offset,   %% 分片偏移量，单位为 8 字节（对应 IPv4 Fragment Offset 字段）
         mf,       %% More Fragments 标志，类型为 boolean()，true 表示还有更多分片
         payload}).   %% 分片所携带的有效数据（二进制）
-record(frag_key,
        {src_ip,     %% 源 IP 地址，类型为 int
         dst_ip,     %% 目标 IP 地址，类型为 int TODO: 是否化为 inet:ip_address()
         id,         %% IP 标识字段（16 位整数）
         protocol}).    %% 协议号（如 6=TCP, 17=UDP）rfc790
