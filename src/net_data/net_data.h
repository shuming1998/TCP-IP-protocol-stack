#ifndef NET_DATA_H
#define NET_DATA_H

#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#define NET_CFG_NETIF_IP              {192, 168, 2, 2}
// 以太网 RFC894 Mac 地址字节大小
#define NET_MAC_ADDR_SIZE             6
#define NET_IPV4_ADDR_SIZE            4
// 以太网每次最大发送数据量：2 字节 CRC + 1514 字节数据
#define NET_DATA_CFG_PACKET_MAX_SIZE  1516

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
}NetProtocol;

typedef enum NetErr {
  NET_ERROR_OK = 0,
  NET_ERROR_IO = -1,
}NetErr;

// 在网络中发送的数据包
typedef struct NetDataPacket {
  uint16_t size;                                    // 包中有效数据大小
  uint8_t *data;                                    // 包中数据的起始地址
  uint8_t payload[NET_DATA_CFG_PACKET_MAX_SIZE];    // 最大负载数据量
}NetDataPacket;

// 处理发送端数据包
NetDataPacket *netPacketAllocForSend(uint16_t dataSize);
// 处理接收端数据包
NetDataPacket *netPacketAllocForRead(uint16_t dataSize);

// 初始化协议栈
void initNet(void);
// 查询协议栈
void queryNet(void);

// ip 地址
typedef union IpAddr {
  uint8_t array[NET_IPV4_ADDR_SIZE];
  uint32_t addr;
}IpAddr;

#define ARP_ENTRY_FREE  0
#define ARP_ENTRY_OK    1

// arp 表
typedef struct ArpEntry {
  IpAddr ipAddr;                        // ip 地址
  uint8_t macAddr[NET_MAC_ADDR_SIZE];   // Mac 地址
  uint8_t state;                        // 当前状态 有效/无效/请求中
  uint16_t ttl;                         // 超时/剩余生存时间
  uint8_t retryCnt;                     // 重试次数
}ArpEntry;

// 初始化 arp 表
void initArp(void);
// 向网络发送 arp 请求包，如果 ip 填本机，就可实现无回报 arp 包的发送
int arpMakeRequest(const IpAddr *ipAddr);
// 处理接收到的 arp 包：检查包 => 处理请求/响应包 => arp 表项更新
void parseRecvedArpPacket(NetDataPacket *packet);

// 打开 pcap 设备接口的封装
NetErr netDriverOpen(uint8_t *macAddr);
// 向网络接口发送数据包的封装
NetErr netDriverSend(NetDataPacket *packet);
// 从网络接口读取数据包的封装
NetErr netDriverRead(NetDataPacket **packet);

#endif