#include "net_data.h"

#define min(a, b) ((a) > (b) ? (b) : (a))

static NetDataPacket sendPacket;
static NetDataPacket recvPacket;

// 发送端数据包：添加包头，向下传递
NetDataPacket *netPacketAllocForSend(uint16_t dataSize) {
  // 要发送的数据放到缓冲空间末尾位置，后续添加包头时，直接根据数据的起始地址向前移动指针
  sendPacket.data = sendPacket.payload + NET_DATA_CFG_PACKET_MAX_SIZE - dataSize;
  sendPacket.size = dataSize;
  return &sendPacket;
}

// 接收端数据包：移除包头，向上传递
NetDataPacket *netPacketAllocForRead(uint16_t dataSize) {
  recvPacket.data = recvPacket.payload;
  recvPacket.size = dataSize;
  return &recvPacket;
}

// 添加包头
static void addHeader(NetDataPacket *packet, uint16_t headerSize) {
  packet->data -= headerSize;
  packet->size += headerSize;
}

// 移除包头
static void removeHeader(NetDataPacket *packet, uint16_t headerSize) {
  packet->data += headerSize;
  packet->size -= headerSize;
}

// 将数据包的大小截断至指定 size
static void truncatePacket(NetDataPacket *packet, uint16_t size) {
  packet->size = min(packet->size, size);
}

void initNet(void) {

}

void queryNet(void) {

}