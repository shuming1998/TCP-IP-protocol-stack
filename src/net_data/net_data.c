#include "net_data.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define convertOrder16(b) ((((b) & 0XFF) << 8) | (((b) >> 8) & 0xFF))
#define ipAddrIsEqualBuf(addr, buf) ((memcmp((addr)->array, (buf), (NET_IPV4_ADDR_SIZE))) == (0))

// 协议栈虚拟网卡 ip 地址
static const IpAddr netifIpAddr = NET_CFG_NETIF_IP;
// 无回报 ARP 广播地址
static const uint8_t bcastEther[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t netifMac[NET_MAC_ADDR_SIZE]; // Network Interface Card Mac 地址

static NetDataPacket sendPacket;
static NetDataPacket recvPacket;
static ArpEntry arpEntry;

uint16_t solveEndian16(uint16_t protocol)
{
	uint16_t a = 0x1234;
	char b =  *(char *)&a;
	if(b == 0x34) {
		return convertOrder16(protocol);
	}
  return protocol;
}

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
static NetErr initEthernet(void) {
  // 将源 Mac 地址写入本地变量
  NetErr err = netDriverOpen(netifMac);
  if (err < 0) {
    return err;
  }

  return arpMakeRequest(&netifIpAddr);
  // return NET_ERROR_OK;
}

// 发送以太网包
static NetErr sendEthernetTo(NetProtocol protocol, const uint8_t *destMac, NetDataPacket *packet) {
  EtherHeader *etherHdr;
  addHeader(packet, sizeof(EtherHeader));                     // 添加以太网包头

  // 开始填充以太网包字段
  etherHdr = (EtherHeader *)packet->data;
  memcpy(etherHdr->sourceMac, netifMac, NET_MAC_ADDR_SIZE);   // 填充源 Mac 地址
  memcpy(etherHdr->destMac, destMac, NET_MAC_ADDR_SIZE);      // 填充目的 Mac 地址
  etherHdr->protocol = solveEndian16(protocol);               // 填充上层协议类型
  return netDriverSend(packet);
}

// 解析以太网包
static void parseEthernet(NetDataPacket *packet) {
  EtherHeader *etherHdr;
  if (packet->size <= sizeof(EtherHeader)) {
    return;
  }

  etherHdr = (EtherHeader *)packet->data;
  uint16_t protocol = solveEndian16(etherHdr->protocol);

  switch (protocol) {
    case NET_PROTOCOL_ARP:
      printf("NET_PROTOCOL_ARP\n");
      // 移除以太网包头
      removeHeader(packet, sizeof(EtherHeader));
      // 解析 arp 包
      parseRecvedArpPacket(packet);
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

void initArp(void) {
  arpEntry.state = ARP_ENTRY_FREE;
}

int arpMakeRequest(const IpAddr *ipAddr) {
  NetDataPacket *packet = netPacketAllocForSend(sizeof(ArpPacket));
  ArpPacket *arpPacket = (ArpPacket *)packet->data;

  arpPacket->hdwrType = ARP_HDWR_ETHER;
  arpPacket->hdwrType = solveEndian16(NET_PROTOCOL_IP);
  arpPacket->hdwrLen = NET_MAC_ADDR_SIZE;
  arpPacket->proLen = NET_IPV4_ADDR_SIZE;
  arpPacket->opcode = solveEndian16(ARP_REQUEST);
  memcpy(arpPacket->senderMac, netifMac, NET_MAC_ADDR_SIZE);
  memcpy(arpPacket->senderIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memset(arpPacket->targetMac, 0, NET_MAC_ADDR_SIZE);
  memcpy(arpPacket->targetIp, ipAddr->array, NET_IPV4_ADDR_SIZE);
  return sendEthernetTo(NET_PROTOCOL_ARP, bcastEther, packet);
}

// 准备 arp 响应包
NetErr arpMakeResponse(ArpPacket *arpPacket) {
  NetDataPacket *packet = netPacketAllocForSend(sizeof(ArpPacket));
  ArpPacket *arpResponsePacket = (ArpPacket *)packet->data;

  arpResponsePacket->hdwrType = ARP_HDWR_ETHER;
  arpResponsePacket->hdwrType = solveEndian16(NET_PROTOCOL_IP);
  arpResponsePacket->hdwrLen = NET_MAC_ADDR_SIZE;
  arpResponsePacket->proLen = NET_IPV4_ADDR_SIZE;
  arpResponsePacket->opcode = solveEndian16(ARP_REPLY);
  memcpy(arpResponsePacket->senderMac, netifMac, NET_MAC_ADDR_SIZE);
  memcpy(arpResponsePacket->senderIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memcpy(arpResponsePacket->targetMac, arpPacket->senderMac, NET_MAC_ADDR_SIZE);
  memcpy(arpResponsePacket->targetIp, arpPacket->senderIp, NET_IPV4_ADDR_SIZE);
  return sendEthernetTo(NET_PROTOCOL_ARP, arpPacket->senderMac, packet);
}

// 更新 arp 表
static void updateArpEntry(uint8_t *senderIp, uint8_t *senderMac) {
  memcpy(arpEntry.ipAddr.array, senderIp, NET_IPV4_ADDR_SIZE);
  memcpy(arpEntry.macAddr, senderMac, NET_MAC_ADDR_SIZE);
  arpEntry.state = ARP_ENTRY_OK;
}

void parseRecvedArpPacket(NetDataPacket *packet) {
  if (packet->size >= sizeof(ArpPacket)) {
    ArpPacket *arpPacketIn = (ArpPacket *)packet->data;
    // 用于判断 arp 包类型：请求/响应？
    uint16_t opcode = solveEndian16(arpPacketIn->opcode);

    // 检查 arp 字段是否合法
    if ((solveEndian16(arpPacketIn->hdwrType)) != ARP_HDWR_ETHER ||
        (arpPacketIn->hdwrLen != NET_MAC_ADDR_SIZE) ||
        (solveEndian16(arpPacketIn->proType) != NET_PROTOCOL_IP) ||
        (arpPacketIn->proLen != NET_IPV4_ADDR_SIZE) ||
        ((opcode != ARP_REQUEST) && (opcode != ARP_REPLY))) {
      return;
    }

    // 检查 target ip ，确定对方的查询对象是自己
    if (!ipAddrIsEqualBuf(&netifIpAddr, arpPacketIn->targetIp)) {
      return;
    }

    switch (opcode) {
      // 处理请求包
      case ARP_REQUEST:
        arpMakeResponse(arpPacketIn);
        // 用源 Mac 和 ip 地址更新 arp 表项
        updateArpEntry(arpPacketIn->senderIp, arpPacketIn->senderMac);
        break;
      // 处理响应包，只更新 arp 表
      case ARP_REPLY:
        // 用源 Mac 和 ip 地址更新 arp 表项
        updateArpEntry(arpPacketIn->senderIp, arpPacketIn->senderMac);
        break;
    }
  }
}

void initNet(void) {
  initEthernet();
  initArp();
}

void queryNet(void) {
  queryEtherNet();
}
