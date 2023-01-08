#ifndef NET_DATA_H
#define NET_DATA_H

#include <stdint.h>

#define NET_CFG_NETIF_IP              { 192, 168, 2, 3 }
#define NET_CFG_DATA_PACKET_MAX_SIZE  1518  // 以太网每次最大发送数据量：4 字节 CRC + 1514 字节数据
#define ARP_CFG_ENTRY_OK_TTL          (5)   // arp 表项超时时间(秒)
#define ARP_CFG_ENTRY_PENDING_TTL     (1)   // arp 表项 PENDING 超时时间(秒)
#define ARP_CFG_MAX_RETRY_TIMES       4     // arp 表项 PENDING 状态下请求次数

#define NET_MAC_ADDR_SIZE             6     // 以太网 RFC894 Mac 地址字节大小
#define NET_IPV4_ADDR_SIZE            4     // 以太网 Ipv4 地址字节大小

/*
以太网 RFC894 数据包格式(最大 1514B，不含 前导码/CRC 等字段)
**************************************************************
*目的Mac地址(6B)|源Mac地址(6B)|上层协议类型(2B)|数据负载(46B~1500B)*
**************************************************************
                               0x0806 ARP     IP 包或 ARP 包
                               0x0800 IP      不足 46B 填充 0
*/
#pragma pack(1)                           // 禁止编译器内存对齐的自动填充
typedef struct EtherHeader {
  uint8_t destMac[NET_MAC_ADDR_SIZE];     // 目的 Mac 地址
  uint8_t sourceMac[NET_MAC_ADDR_SIZE];   // 源 Mac 地址
  uint16_t protocol;                      // 上层协议类型
}EtherHeader;
#pragma pack()

#define ARP_HDWR_ETHER  0x1               // 以太网
#define ARP_REQUEST     0X1               // ARP请求包
#define ARP_REPLY       0X2               // ARP响应包
#define ARP_RARP        0x3               // RARP包

#pragma pack(1)
// arp 包
typedef struct ArpPacket {
  uint16_t hdwrType;                      // 硬件类型
  uint16_t proType;                       // 协议类型
  uint8_t hdwrLen;                        // 硬件地址长度
  uint8_t proLen;                         // 协议地址长度
  uint16_t opcode;                        // 请求/响应
  uint8_t senderMac[NET_MAC_ADDR_SIZE];   // 发送方硬件地址
  uint8_t senderIp[NET_IPV4_ADDR_SIZE];   // 发送方协议地址
  uint8_t targetMac[NET_MAC_ADDR_SIZE];   // 接收方硬件地址
  uint8_t targetIp[NET_IPV4_ADDR_SIZE];   // 接收方协议地址
}ArpPacket;
#pragma pack()

typedef enum NetProtocol {
  NET_PROTOCOL_IP = 0x0800,
  NET_PROTOCOL_ARP = 0x0806,
  NET_PROTOCOL_ICMP = 1,
}NetProtocol;

typedef enum NetErr {
  NET_ERROR_OK = 0,
  NET_ERROR_IO = -1,
  NET_ERROR_NONE = -2,
}NetErr;

// 在网络中发送的数据包
typedef struct NetPacket {
  uint16_t size;                                    // 包中有效数据大小
  uint8_t *data;                                    // 包中数据的起始地址
  uint8_t payload[NET_CFG_DATA_PACKET_MAX_SIZE];    // 最大负载数据量
}NetPacket;

// 处理发送端数据包
NetPacket *netPacketAllocForSend(uint16_t dataSize);
// 处理接收端数据包
NetPacket *netPacketAllocForRead(uint16_t dataSize);

// ip 地址
typedef union IpAddr {
  uint8_t array[NET_IPV4_ADDR_SIZE];
  uint32_t addr;
}IpAddr;

// arp 表项状态
#define ARP_ENTRY_FREE    0 // arp 表项空闲
#define ARP_ENTRY_OK      1 // arp 表项解析成功
#define ARP_ENTRY_PENDING 2 // arp 表项正在解析
#define ARP_TIMER_PERIOD  1 // arp 表项扫描周期

// arp 表
typedef struct ArpEntry {
  IpAddr ipAddr;                        // ip 地址
  uint8_t macAddr[NET_MAC_ADDR_SIZE];   // Mac 地址
  uint8_t state;                        // 当前状态 有效/无效/请求中
  uint16_t ttl;                         // 当前超时时间
  uint8_t retryCnt;                     // 当前重试次数
}ArpEntry;

typedef uint32_t net_time_t;            // 当前运行时长
// 获取程序从启动到目前为止的运行时长
const net_time_t getNetRunsTime(void);
// 判断此时是否应检查 arp 表
int checkArpEntryTtl(net_time_t *time, uint32_t sec);

// 初始化 arp 表
void initArp(void);
// 向网络发送 arp 请求包，如果 ip 填本机，就可实现无回报 arp 包的发送
NetErr arpMakeRequest(const IpAddr *ipAddr);
// 处理接收到的 arp 包：检查包 => 处理请求/响应包 => arp 表项更新
void parseRecvedArpPacket(NetPacket *packet);
// 查询 arp 表
void queryArpEntry(void);
// 通过 arp 解析将 ipAddr 对应的 Mac 地址读入到 macAddr
NetErr arpResolve(const IpAddr *ipAddr, uint8_t **macAddr);


//=============IP begin=============//
#define NET_VERSION_IPV4  4
#define NET_IP_PACKET_TTL 64
#pragma pack(1)
// ip 数据包头
typedef struct IpHeader {
  uint8_t headerLen : 4;                // 头部长度，第一个字节的低四位
  uint8_t version : 4;                  // 版本，第一个字节的高四位
  uint8_t tos;                          // 服务类型
  uint16_t totalLen;                    // 总长度
  uint16_t id;                          // 数据包 id
  uint16_t flagsFragment;               // 3 位标志位 & 13 位分片偏移
  uint8_t ttl;                          // 生存时间
  uint8_t protocol;                     // 上层协议类型
  uint16_t hdrChecksum;                 // 校验和
  uint8_t sourceIp[NET_IPV4_ADDR_SIZE]; // 源 ip 地址
  uint8_t destIp[NET_IPV4_ADDR_SIZE];   // 目的 ip 地址
}IpHeader;
#pragma pack()

// 初始化 ip
void initIp(void);
// 处理输入的 ip 数据包
void parseRecvedIpPacket(NetPacket *packet);
// 发送 ip 数据包
NetErr sendIpPacketTo(NetProtocol protocol, IpAddr *destIp, NetPacket *packet);
//=============IP end=============//

//=============ICMP begin=============//
#define ICMP_CODE_ECHO_REQUEST  8
#define ICMP_CODE_ECHO_REPLY    0

#pragma pack(1)
// ICMP 包头
typedef struct IcmpHeader {
  uint8_t type;                         // icmp 包类型  Echo(ping) request
  uint8_t code;                         // 对于 Echo, 固定为 0
  uint16_t checksum;                    // icmp 报文校验和
  uint16_t id;                          // icmp 报文标识符
  uint16_t seq;                         // icmp 报文序号   id + seq 可唯一对应一条 request/reply
}IcmpHeader;
#pragma pack()

// 初始化 icmp
void initIcmp(void);
// 处理输入的 icmp 数据包
void parseRecvedIcmpPacket(IpAddr *sourceIp, NetPacket *packet);
//=============ICMP end=============//


// 打开 pcap 设备接口的封装
NetErr netDriverOpen(uint8_t *macAddr);
// 向网络接口发送数据包的封装
NetErr netDriverSend(NetPacket *packet);
// 从网络接口读取数据包的封装
NetErr netDriverRead(NetPacket **packet);

// 初始化协议栈
void initNet(void);
// 查询协议栈
void queryNet(void);

#endif