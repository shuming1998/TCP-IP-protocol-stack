#include "net_data.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) > (b) ? (b) : (a))
#define convertOrder16(b) ((((b) & 0XFF) << 8) | (((b) >> 8) & 0xFF))
#define ipAddrIsEqualBuf(addr, buf) (memcmp((addr)->array, (buf), NET_IPV4_ADDR_SIZE) == 0)
#define ipAddrIsEqual(addrLhs, addrRhs) ((addrLhs)->addr == (addrRhs)->addr)

// 协议栈虚拟网卡 ip 地址
static const IpAddr netifIpAddr = NET_CFG_NETIF_IP;
// 无回报 ARP 广播地址
static const uint8_t bcastEther[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t netifMac[NET_MAC_ADDR_SIZE]; // Network Interface Card Mac 地址

static NetPacket sendPacket;            // 接收缓冲
static NetPacket recvPacket;            // 发送缓冲
static ArpEntry arpEntry;                   // arp 单表项
static net_time_t  arpTimer;                // arp 定时查询时间

int checkArpEntryTtl(net_time_t *time, uint32_t sec) {
  net_time_t curRunsTime = getNetRunsTime();

  // 初始化时 sec 实参为 0
  if (0 == sec) {
    // 记录上次程序运行时间
    *time = curRunsTime;
    return 0;
  // 检查超时时间，此时 sec 为间隔扫描时间： 1 秒
  } else if (curRunsTime - *time >= sec) {
    // 记录上次程序运行时间
    *time = curRunsTime;
    return 1;
  }

  return 0;
}

// 本地字节序转网络字节序
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
NetPacket *netPacketAllocForSend(uint16_t dataSize) {
  // 要发送的数据放到缓冲空间末尾位置，后续添加包头时，直接根据数据的起始地址向前移动指针
  sendPacket.data = sendPacket.payload + NET_CFG_DATA_PACKET_MAX_SIZE - dataSize;
  sendPacket.size = dataSize;
  return &sendPacket;
}

// 接收端数据包：移除包头，向上传递
NetPacket *netPacketAllocForRead(uint16_t dataSize) {
  recvPacket.data = recvPacket.payload;
  recvPacket.size = dataSize;
  return &recvPacket;
}

// 添加包头
static void addHeader(NetPacket *packet, uint16_t headerSize) {
  packet->data -= headerSize;
  packet->size += headerSize;
}

// 移除包头
static void removeHeader(NetPacket *packet, uint16_t headerSize) {
  packet->data += headerSize;
  packet->size -= headerSize;
}

// 将数据包的大小截断至指定 size
static void truncatePacket(NetPacket *packet, uint16_t size) {
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
static NetErr sendEthernetTo(NetProtocol protocol, const uint8_t *destMac, NetPacket *packet) {
  EtherHeader *etherHdr;

  addHeader(packet, sizeof(EtherHeader));                     // 添加以太网包头
  etherHdr = (EtherHeader *)packet->data;                     // 填充以太网包字段
  memcpy(etherHdr->destMac, destMac, NET_MAC_ADDR_SIZE);      // 填充目的 Mac 地址
  memcpy(etherHdr->sourceMac, netifMac, NET_MAC_ADDR_SIZE);   // 填充源 Mac 地址
  etherHdr->protocol = solveEndian16(protocol);               // 填充上层协议类型

  return netDriverSend(packet);
}

// 通过以太网发送 ip 数据包
static NetErr sendByEthernet(IpAddr *destIp, NetPacket *packet) {
  // 通过 arp 将 ip 地址转换为 mac 地址
  NetErr err;
  uint8_t *macAddr;

  if ((err = arpResolve(destIp, &macAddr)) == NET_ERROR_OK) {
    return sendEthernetTo(NET_PROTOCOL_IP, macAddr, packet);
  }

  return err;
}

// 解析以太网包
static void parseEthernet(NetPacket *packet) {
  printf("recv ethernet packet!\n");
  if (packet->size <= sizeof(EtherHeader)) {
    printf("packet->size <= sizeof(EtherHeader)!\n");
    return;
  }

  EtherHeader *etherHdr = (EtherHeader *)packet->data;

  switch (solveEndian16(etherHdr->protocol)) {
    case NET_PROTOCOL_ARP:
      printf("NET_PROTOCOL_ARP\n");
      removeHeader(packet, sizeof(EtherHeader));  // 移除以太网包头
      parseRecvedArpPacket(packet);               // 解析 arp 包
      break;
    case NET_PROTOCOL_IP:
      printf("NET_PROTOCOL_IP\n");
      removeHeader(packet, sizeof(EtherHeader));  // 移除以太网包头
      parseRecvedIpPacket(packet);                // 解析 ip 包
      break;
    default:
      printf("ping...\n");
      break;
  }
}

// 查询是否有以太网包
static void queryEtherNet(void) {
  NetPacket *packet;

  if (netDriverRead(&packet) == NET_ERROR_OK) {
    parseEthernet(packet);
  }
}

void initArp(void) {
  arpEntry.state = ARP_ENTRY_FREE;

  // 获取初始时间
  checkArpEntryTtl(&arpTimer, 0);
}

NetErr arpMakeRequest(const IpAddr *ipAddr) {
  NetPacket *packet = netPacketAllocForSend(sizeof(ArpPacket));

  ArpPacket *arpPacket = (ArpPacket *)packet->data;
  arpPacket->hdwrType = solveEndian16(ARP_HDWR_ETHER);
  arpPacket->proType = solveEndian16(NET_PROTOCOL_IP);
  arpPacket->hdwrLen = NET_MAC_ADDR_SIZE;
  arpPacket->proLen = NET_IPV4_ADDR_SIZE;
  arpPacket->opcode = solveEndian16(ARP_REQUEST);
  memcpy(arpPacket->senderMac, netifMac, NET_MAC_ADDR_SIZE);
  memcpy(arpPacket->senderIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memset(arpPacket->targetMac, 0, NET_MAC_ADDR_SIZE);
  memcpy(arpPacket->targetIp, ipAddr->array, NET_IPV4_ADDR_SIZE);

  return sendEthernetTo(NET_PROTOCOL_ARP, bcastEther, packet);
}

// 生成 arp 响应包
NetErr arpMakeResponse(ArpPacket *arpPacket) {
  NetPacket *packet = netPacketAllocForSend(sizeof(ArpPacket));

  ArpPacket *arpResponsePacket = (ArpPacket *)packet->data;
  arpResponsePacket->hdwrType = solveEndian16(ARP_HDWR_ETHER);
  arpResponsePacket->proType = solveEndian16(NET_PROTOCOL_IP);
  arpResponsePacket->hdwrLen = NET_MAC_ADDR_SIZE;
  arpResponsePacket->proLen = NET_IPV4_ADDR_SIZE;
  arpResponsePacket->opcode = solveEndian16(ARP_REPLY);
  memcpy(arpResponsePacket->senderMac, netifMac, NET_MAC_ADDR_SIZE);
  memcpy(arpResponsePacket->senderIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memcpy(arpResponsePacket->targetMac, arpPacket->senderMac, NET_MAC_ADDR_SIZE);
  memcpy(arpResponsePacket->targetIp, arpPacket->senderIp, NET_IPV4_ADDR_SIZE);

  // arpPacket->senderMac
  return sendEthernetTo(NET_PROTOCOL_ARP, bcastEther, packet);
}

NetErr arpResolve(const IpAddr *ipAddr, uint8_t **macAddr) {
  if ((arpEntry.state == ARP_ENTRY_OK) && ipAddrIsEqual(ipAddr, &arpEntry.ipAddr)) {
    *macAddr = arpEntry.macAddr;
    return NET_ERROR_OK;
  }

  arpMakeRequest(ipAddr);
  return NET_ERROR_IO;
}

//  根据接收到的 arp 响应包，更新 arp 表项
static void updateArpEntry(uint8_t *senderIp, uint8_t *senderMac) {
  memcpy(arpEntry.ipAddr.array, senderIp, NET_IPV4_ADDR_SIZE);
  memcpy(arpEntry.macAddr, senderMac, NET_MAC_ADDR_SIZE);
  arpEntry.state = ARP_ENTRY_OK;
  arpEntry.ttl = ARP_CFG_ENTRY_OK_TTL;
  arpEntry.retryCnt = ARP_CFG_MAX_RETRY_TIMES;
}

void parseRecvedArpPacket(NetPacket *packet) {
  if (packet->size >= sizeof(ArpPacket)) {
    ArpPacket *arpPacketIn = (ArpPacket *)packet->data;
    // 用于判断 arp 包类型：请求/响应？
    uint16_t opcode = solveEndian16(arpPacketIn->opcode);

    // 检查 arp 字段是否合法
    if ((solveEndian16(arpPacketIn->hdwrType) != ARP_HDWR_ETHER) ||
        (arpPacketIn->hdwrLen != NET_MAC_ADDR_SIZE) ||
        (solveEndian16(arpPacketIn->proType) != NET_PROTOCOL_IP) ||
        (arpPacketIn->proLen != NET_IPV4_ADDR_SIZE) ||
        ((opcode != ARP_REQUEST) && (opcode != ARP_REPLY))) {
      return;
    }

    // 检查 target ip ，确定对方的查询对象是自己
    if (!ipAddrIsEqualBuf(&netifIpAddr, arpPacketIn->targetIp)) {
      printf("arp packet targetIp != netifIpAddr!\n");
      return;
    }
    printf("arp packet targetIp == netifIpAddr!\n");
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

void queryArpEntry() {
  // 每隔一定时间才去查 arp 表项
  if (checkArpEntryTtl(&arpTimer, ARP_TIMER_PERIOD)) {
    switch (arpEntry.state) {
      // case ARP_ENTRY_FREE:
      //   arpMakeRequest(&arpEntry.ipAddr);
      //   break;
      case ARP_ENTRY_OK:
        if (0 == --arpEntry.ttl) {
          arpMakeRequest(&arpEntry.ipAddr);         // arp 表项超时，重新获取该超时的 arp 表项
          arpEntry.state = ARP_ENTRY_PENDING;       // 更新 arp 表项状态为：正在查询
          arpEntry.ttl = ARP_CFG_ENTRY_PENDING_TTL; // 设置 PENDING 状态的 arp 表项响应包的超时时间
        }
        break;
      case ARP_ENTRY_PENDING:
        if (0 == --arpEntry.ttl) {                  // 判断 PENDING 状态 arp 包的响应时间是否超时
          if (0 == arpEntry.retryCnt--) {           // 响应时间超时，并且重试次数为 0，直接 free 表项
            arpEntry.state = ARP_ENTRY_FREE;
          } else {                                  // 响应事件超时，且剩余请求次数，尝试重新获取 arp 响应包
            arpMakeRequest(&arpEntry.ipAddr);
            arpEntry.state = ARP_ENTRY_PENDING;
            arpEntry.ttl = ARP_CFG_ENTRY_PENDING_TTL;
          }
        }
        break;
    }
  }
}

// 16 位校验和算法
static uint16_t checksum16(uint16_t *buf, uint16_t len, uint16_t preSum, int complement) {
  uint32_t checksum = preSum;
  uint16_t high;  // 32 位校验和的高 16 位

  // 对IP头部中的每 16bit 进行二进制求和
  while (len > 1) {
    checksum += *buf++;
    len -= 2;
  }

  // 奇数字节
  if (len > 0) {
    checksum += *(uint8_t *)buf;
  }

  // 若和的高 16bit != 0，将和的高 16bit 和低 16bit 反复相加，直到高 16bit = 0，获得一个16bit的值
  while ((high = checksum >> 16) != 0) {
    checksum = high + (checksum & 0XFFFF);
  }

  // 校验和取反
  return (uint16_t)~checksum;
}

void initIp(void) {

}

void parseRecvedIpPacket(NetPacket *packet) {
  IpHeader *ipHdr = (IpHeader *)packet->data;
  uint32_t headerSize;
  uint32_t totalSize;
  uint16_t preChecksum;

  printf("check ip packet version!\n");
  if (ipHdr->version != NET_VERSION_IPV4) {
    printf("ip packet version not ipv4!\n");
    return;
  }

  headerSize = ipHdr->headerLen * 4;
  totalSize = solveEndian16(ipHdr->totalLen);
  if ((headerSize < sizeof(IpHeader)) || (totalSize < headerSize)) {
    printf("invalid ip packet size!\n");
    return;
  }

  preChecksum = ipHdr->hdrChecksum;
  ipHdr->hdrChecksum = 0;
  if (preChecksum != checksum16((uint16_t *)ipHdr, headerSize, 0, 1)) {
    printf("invalid checksum!\n");
    return;
  }

  printf("check ip packet dest ip addr!\n");
  // 检查 ip 数据包是否是发送给自己的
  if (ipAddrIsEqualBuf(&netifIpAddr, ipHdr->destIp)) {
    return;
  }
  printf("check ip packet protocol!\n");
  switch (ipHdr->protocol) {
    // case ICMP:
    //   break;
    default:
      break;
  }
}

NetErr sendIpPacketTo(NetProtocol protocol, IpAddr *destIp, NetPacket *packet) {
  static uint32_t ipPacketId = 0;
  IpHeader *ipHdr;

  // 设置 ip 数据包头部
  addHeader(packet, sizeof(IpHeader));
  ipHdr = (IpHeader *)packet->data;
  ipHdr->version = NET_VERSION_IPV4;
  ipHdr->headerLen = sizeof(IpHeader) / 4;
  ipHdr->tos = 0;
  ipHdr->totalLen = solveEndian16(packet->size);
  ipHdr->id = solveEndian16(ipPacketId);
  ipHdr->flagsFragment = 0;
  ipHdr->ttl = NET_IP_PACKET_TTL;
  ipHdr->protocol = protocol;
  memcpy(ipHdr->sourceIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memcpy(ipHdr->destIp, destIp->array, NET_IPV4_ADDR_SIZE);
  ipHdr->hdrChecksum = 0; // 计算校验和之前必须先置为 0
  ipHdr->hdrChecksum = checksum16((uint16_t *)ipHdr, sizeof(IpHeader), 0, 1);

  ++ipPacketId;

  return sendByEthernet(destIp, packet);
}

void initNet(void) {
  initEthernet();
  initArp();
  initIp();
}

void queryNet(void) {
  queryEtherNet();
  queryArpEntry();
}
