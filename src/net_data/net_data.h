#ifndef NET_DATA_H
#define NET_DATA_H

#include <stdint.h>
#include <pcap.h>

// 以太网每次最大发送数据量：2 字节 CRC + 1514 字节数据
#define NET_DATA_CFG_PACKET_MAX_SIZE 1516

typedef enum netErr {
  NET_ERROR_OK = 0,
  NET_ERROR_IO = -1,
}netErr;

typedef struct NetDataPacket {
  uint16_t size;                                  // 包中有效数据大小
  uint8_t *data;                                  // 包中数据的起始地址
  uint8_t payload[NET_DATA_CFG_PACKET_MAX_SIZE];  // 最大负载数据量
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