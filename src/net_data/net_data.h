#ifndef NET_DATA_H
#define NET_DATA_H

#include <stdint.h>
#include <pcap.h>
#include <string.h>

// 以太网每次最大发送数据量：2 字节 CRC + 1514 字节数据
#define NET_DATA_CFG_PACKET_MAX_SIZE 1516
// 以太网 RFC894 Mac 地址字节大小
#define NET_MAC_ADDR_SIZE 6

/*
以太网 RFC894 数据包格式(最大 1514B，不含 前导码/CRC 等字段)
**************************************************************
*目的Mac地址(6B)|源Mac地址(6B)|上层协议类型(2B)|数据负载(46B~1500B)*
**************************************************************
                               0x0806 ARP     IP 包或 ARP 包
                               0x0800 IP      不足 46B 填充 0
*/
#pragma pack(1) // 禁止编译器内存对齐的自动填充
typedef struct etherHeader {
  uint8_t destMac[NET_MAC_ADDR_SIZE];     // 目的 Mac 地址
  uint8_t sourceMac[NET_MAC_ADDR_SIZE];   // 源 Mac 地址
  uint16_t protocol;                      // 上层协议类型
}etherHeader;
#pragma pack()

typedef enum netProtocol {
  NET_PROTOCOL_IP = 0x0800,
  NET_PROTOCOL_ARP = 0x0806,
}netProtocol;

typedef enum netErr {
  NET_ERROR_OK = 0,
  NET_ERROR_IO = -1,
}netErr;

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

// 打开 pcap 设备接口的封装
netErr netDriverOpen(uint8_t *macAddr);
// 向网络接口发送数据包的封装
netErr netDriverSend(NetDataPacket *packet);
// 从网络接口读取数据包的封装
netErr netDriverRead(NetDataPacket **packet);

#endif