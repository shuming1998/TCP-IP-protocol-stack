#include "net_data.h"


#define min(a, b) ((a) > (b) ? (b) : (a))

#define convertOrder16(b) (((b) & 0XFF) << 8) | (((b) >> 8) & 0xFF)

static uint8_t netifMac[NET_MAC_ADDR_SIZE]; // Network Interface Card Mac

static NetDataPacket sendPacket;
static NetDataPacket recvPacket;

uint16_t solveEndian16(uint16_t protocol);

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

// 初始化以太网
static netErr initEthernet(void) {
  // 将源 Mac 地址写入本地变量
  netErr err = netDriverOpen(netifMac);
  if (err < 0) {
    return err;
  }
  return NET_ERROR_OK;
}

// 发送以太网包
static netErr sendEthernetTo(netProtocol protocol, const uint8_t *destMac, NetDataPacket *packet) {
  addHeader(packet, sizeof(etherHeader));                     // 添加以太网包头

  // 开始填充以太网包字段
  etherHeader *etherHdr = (etherHeader *)packet->data;
  memcpy(etherHdr->destMac, destMac, NET_MAC_ADDR_SIZE);      // 填充目的 Mac 地址
  memcpy(etherHdr->sourceMac, netifMac, NET_MAC_ADDR_SIZE);   // 填充源 Mac 地址
  etherHdr->protocol = solveEndian16(protocol);               // 填充上层协议类型

  return netDriverSend(packet);
}

// 解析以太网包
static void parseEthernet(NetDataPacket *packet) {
  if (packet->size <= sizeof(etherHeader)) {
    return;
  }

  etherHeader *etherHdr = (etherHeader *)packet->data;
  uint16_t protocol = solveEndian16(etherHdr->protocol);

  switch (protocol) {
    case NET_PROTOCOL_ARP:
      printf("NET_PROTOCOL_ARP\n");
      break;
    case NET_PROTOCOL_IP:
      printf("NET_PROTOCOL_IP\n");
      break;
    default:
      printf("ping...\n");
  }
}

// 查询是否有以太网包
static void queryEtherNet(void) {
  NetDataPacket *packet;
  if (netDriverRead(&packet) == NET_ERROR_OK) {
    parseEthernet(packet);
  }
}

void initNet(void) {
  initEthernet();
}

void queryNet(void) {
  queryEtherNet();
}

uint16_t solveEndian16(uint16_t protocol)
{
	uint16_t a = 0x1234;
	char b =  *(char *)&a;
	if(b == 0x34) {
		return convertOrder16(protocol);
	}
  return protocol;
}