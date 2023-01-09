#include "net_data.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) > (b) ? (b) : (a))
#define convertOrder16(b) ((((b) & 0XFF) << 8) | (((b) >> 8) & 0xFF))
#define ipAddrIsEqualBuf(addr, buf) (memcmp((addr)->array, (buf), NET_IPV4_ADDR_SIZE) == 0)
#define ipAddrIsEqual(addrLhs, addrRhs) ((addrLhs)->addr == (addrRhs)->addr)
#define getIpFromBuf(dest, buf) ((dest)->addr = *(uint32_t *)(buf))

// 协议栈虚拟网卡 ip 地址
static const IpAddr netifIpAddr = NET_CFG_NETIF_IP;
// 无回报 ARP 广播地址
static const uint8_t bcastEther[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t netifMac[NET_MAC_ADDR_SIZE];     // Network Interface Card Mac 地址

static NetPacket sendPacket;                    // 接收缓冲
static NetPacket recvPacket;                    // 发送缓冲
static ArpEntry arpEntry;                       // arp 单表项
static net_time_t  arpTimer;                    // arp 定时查询时间
static UdpBlk udpSocket[UDP_CFG_MAX_UDP];

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
uint16_t solveEndian16(uint16_t protocol) {
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
static void addHdr(NetPacket *packet, uint16_t hdrSize) {
  packet->data -= hdrSize;
  packet->size += hdrSize;
}

// 移除包头
static void rmHdr(NetPacket *packet, uint16_t hdrSize) {
  packet->data += hdrSize;
  packet->size -= hdrSize;
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
static NetErr sendEthernetTo(NetProtocol protocol, const uint8_t *dstMac, NetPacket *packet) {
  EtherHdr *etherHdr;

  addHdr(packet, sizeof(EtherHdr));                         // 添加以太网包头
  etherHdr = (EtherHdr *)packet->data;                      // 填充以太网包字段
  memcpy(etherHdr->dstMac, dstMac, NET_MAC_ADDR_SIZE);      // 填充目的 Mac 地址
  memcpy(etherHdr->srcMac, netifMac, NET_MAC_ADDR_SIZE);    // 填充源 Mac 地址
  etherHdr->protocol = solveEndian16(protocol);             // 填充上层协议类型

  return netDriverSend(packet);
}

// 通过以太网发送 ip 数据包
static NetErr sendByEthernet(IpAddr *destIp, NetPacket *packet) {
  // 通过 arp 将 ip 地址转换为 mac 地址
  NetErr err;
  uint8_t *macAddr;

  if ((err = arpResolve(destIp, &macAddr) == NET_ERROR_OK)) {
    return sendEthernetTo(NET_PROTOCOL_IP, macAddr, packet);
  }

  return err;
}

// 解析以太网包
static void parseEthernet(NetPacket *packet) {
  if (packet->size <= sizeof(EtherHdr)) {
    printf("packet->size <= sizeof(EtherHdr)!\n");
    return;
  }

  EtherHdr *etherHdr = (EtherHdr *)packet->data;

  switch (solveEndian16(etherHdr->protocol)) {
    case NET_PROTOCOL_ARP:
      printf("NET_PROTOCOL_ARP\n");
      rmHdr(packet, sizeof(EtherHdr));  // 移除以太网包头
      parseRecvedArpPacket(packet);               // 解析 arp 包
      break;
    case NET_PROTOCOL_IP:
      printf("NET_PROTOCOL_IP\n");
      rmHdr(packet, sizeof(EtherHdr));  // 移除以太网包头
      parseRecvedIpPacket(packet);                // 解析 ip 包
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
  return NET_ERROR_NONE;
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

    switch (solveEndian16(arpPacketIn->opcode)) {
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
      case ARP_ENTRY_OK:
        if (--arpEntry.ttl == 0) {
          arpMakeRequest(&arpEntry.ipAddr);         // arp 表项超时，重新获取该超时的 arp 表项
          arpEntry.state = ARP_ENTRY_PENDING;       // 更新 arp 表项状态为：正在查询
          arpEntry.ttl = ARP_CFG_ENTRY_PENDING_TTL; // 设置 PENDING 状态的 arp 表项响应包的超时时间
        }
        break;
      case ARP_ENTRY_PENDING:
        if (--arpEntry.ttl == 0) {                  // 判断 PENDING 状态 arp 包的响应时间是否超时
          if (arpEntry.retryCnt-- == 0) {           // 响应时间超时，并且重试次数为 0，直接 free 表项
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
    checksum = high + (checksum & 0Xffff);
  }

  // 校验和取反
  return complement ? (uint16_t)~checksum : (uint16_t)checksum;
}

void initIp(void) {}

void parseRecvedIpPacket(NetPacket *packet) {
  IpHdr *ipHdr = (IpHdr *)packet->data;
  uint32_t hdrSize, totalSize;
  uint16_t preChecksum;
  IpAddr srcIp;

  printf("check ip packet version!\n");
  if (ipHdr->version != NET_VERSION_IPV4) {
    printf("ip packet version not ipv4!\n");
    return;
  }

  hdrSize = ipHdr->hdrLen * 4;
  totalSize = solveEndian16(ipHdr->totalLen);
  if ((hdrSize < sizeof(IpHdr)) || ((totalSize < hdrSize) || (packet->size < totalSize))) {
    printf("invalid ip packet size!\n");
    return;
  }

  preChecksum = ipHdr->hdrChecksum;
  ipHdr->hdrChecksum = 0;
  if (preChecksum != checksum16((uint16_t *)ipHdr, hdrSize, 0, 1)) {
    printf("invalid checksum!\n");
    return;
  }
  ipHdr->hdrChecksum = preChecksum;

  printf("check ip packet dest ip addr!\n");
  // 只处理发送给自己的 ip 数据包
  if (!ipAddrIsEqualBuf(&netifIpAddr, ipHdr->destIp)) {
    return;
  }

  // 从包头中提取 srcIp
  getIpFromBuf(&srcIp, ipHdr->srcIp);
  printf("ipHdr->protocol: %d", ipHdr->protocol);

  switch (ipHdr->protocol) {
    case NET_PROTOCOL_UDP:
      printf("NET_PROTOCOL_UDP\n");
      if (packet->size >= sizeof(UdpHdr)) {
        // 获取 udp 包头
        UdpHdr *udpHdr = (UdpHdr *)(packet->data + hdrSize);
        // 先查找对应的 udp 控制块
        UdpBlk *udp = findUdpBlk(solveEndian16(udpHdr->destPort));
        // 然后传给 udp 包解析函数
        if (udp) {
          // 移除 udp 包头
          rmHdr(packet, hdrSize);
          // 处理 udp 数据包
          parseRecvedUdpPacket(udp, &srcIp, packet);
        } else if (!udp) {
          destIcmpUnreach(ICMP_CODE_PORT_UNREACHABLE, ipHdr);
        }
      }
      break;
    case NET_PROTOCOL_ICMP:
      printf("NET_PROTOCOL_ICMP\n");
      rmHdr(packet, hdrSize);
      parseRecvedIcmpPacket(&srcIp, packet);
      break;
    default:
      // 其他协议不可达
      destIcmpUnreach(ICMP_CODE_PROTO_UNREACHABLE, ipHdr);
      break;
  }
}

NetErr sendIpPacketTo(NetProtocol protocol, IpAddr *destIp, NetPacket *packet) {
  static uint32_t ipPacketId = 0;
  IpHdr *ipHdr;

  // 设置 ip 数据包头部
  addHdr(packet, sizeof(IpHdr));
  ipHdr = (IpHdr *)packet->data;
  ipHdr->version = NET_VERSION_IPV4;
  ipHdr->hdrLen = sizeof(IpHdr) / 4;
  ipHdr->tos = 0;
  ipHdr->totalLen = solveEndian16(packet->size);
  ipHdr->id = solveEndian16(ipPacketId);
  ipHdr->flagsFragment = 0;
  ipHdr->ttl = NET_IP_PACKET_TTL;
  ipHdr->protocol = protocol;
  memcpy(ipHdr->srcIp, netifIpAddr.array, NET_IPV4_ADDR_SIZE);
  memcpy(ipHdr->destIp, destIp->array, NET_IPV4_ADDR_SIZE);
  ipHdr->hdrChecksum = 0; // 计算校验和之前必须先置为 0
  ipHdr->hdrChecksum = checksum16((uint16_t *)ipHdr, sizeof(IpHdr), 0, 1);

  ++ipPacketId;

  return sendByEthernet(destIp, packet);
}


void initIcmp(void) {}

static NetErr replyIcmpRequest(IcmpHdr *icmpHdr, IpAddr *srcIp, NetPacket *packet) {
  // icmp 响应包的大小和请求包的大小相同
  NetPacket *respPkt = netPacketAllocForSend(packet->size);

  IcmpHdr *icmpReplyHdr = (IcmpHdr *)respPkt->data;
  icmpReplyHdr->type = ICMP_CODE_ECHO_REPLY;
  icmpReplyHdr->code = 0;
  icmpReplyHdr->id = icmpHdr->id;
  icmpReplyHdr->seq = icmpHdr->seq;
  // 拷贝 icmp 数据段
  memcpy(((uint8_t *)icmpReplyHdr) + sizeof(IcmpHdr),
        ((uint8_t *)icmpHdr) + sizeof(IcmpHdr),
        packet->size - sizeof(IcmpHdr));
  icmpReplyHdr->checksum = 0;
  icmpReplyHdr->checksum = checksum16((uint16_t *)icmpReplyHdr, respPkt->size, 0, 1);

  return sendIpPacketTo(NET_PROTOCOL_ICMP, srcIp, respPkt);
}

void parseRecvedIcmpPacket(IpAddr *srcIp, NetPacket *packet) {
  IcmpHdr *icmpHdr = (IcmpHdr *)packet->data;

  if ((packet->size >= sizeof(IcmpHdr)) && (icmpHdr->type == ICMP_CODE_ECHO_REQUEST)) {
    replyIcmpRequest(icmpHdr, srcIp, packet);
  }
}

NetErr destIcmpUnreach(uint8_t code, IpHdr *ipHdr) {
  IpAddr destIp;
  getIpFromBuf(&destIp, ipHdr->srcIp);

  // 计算 icmp 不可达报文长度
  uint16_t ipHdrSize = ipHdr->hdrLen * 4;
  uint16_t ipDataSize = solveEndian16(ipHdr->totalLen) - ipHdrSize;
  ipDataSize = ipHdrSize + min(ipDataSize, ICMP_DATA_ORIGINAL);
  NetPacket *packet = netPacketAllocForSend(sizeof(IcmpHdr) + ipDataSize);

  IcmpHdr *icmpHdr = (IcmpHdr *)packet->data;
  icmpHdr->type = ICMP_TYPE_UNREACHABLE;
  icmpHdr->code = code;
  icmpHdr->id = 0;   // unused
  icmpHdr->seq = 0;  // unused
  // 拷贝 icmp 数据段到 ipmp 头部后面
  memcpy(((uint8_t *)icmpHdr) + sizeof(IcmpHdr), ipHdr, ipDataSize);
  icmpHdr->checksum = 0;
  icmpHdr->checksum = checksum16((uint16_t *)icmpHdr, packet->size, 0, 1);

  return sendIpPacketTo(NET_PROTOCOL_ICMP, &destIp, packet);
}

void initUpd(void) {
  memset(udpSocket, 0, sizeof(udpSocket));
}

UdpBlk *getUdpBlk(udpHandler handler) {
  UdpBlk *udp, *end;

  for (udp = udpSocket, end = &udpSocket[UDP_CFG_MAX_UDP]; udp < end; ++udp) {
    if (udp->state == UDP_STATE_FREE) {
      udp->state = UDP_STATE_USED;
      udp->localPort = 0;
      udp->handler = handler;
      return udp;
    }
  }

  return (UdpBlk *)0;
}

void freeUdpBlk(UdpBlk *udpBlk) {
  udpBlk->state = UDP_STATE_FREE;
}

UdpBlk *findUdpBlk(uint16_t port) {
  UdpBlk *cur, *end;

  for (cur = udpSocket, end = &udpSocket[UDP_CFG_MAX_UDP]; cur < end; ++cur) {
    if ((cur->state == UDP_STATE_USED) && (cur->localPort == port)) {
      return cur;
    }
  }

  return (UdpBlk *)0;
}

NetErr bindUdpBlk(UdpBlk *udpBlk, uint16_t localPort) {
  UdpBlk *cur, *end;
  // 0 号端口有特定用途
  if (localPort == 0) {
    return NET_ERR_PORT_USED;
  }

  for (cur = udpSocket, end = &udpSocket[UDP_CFG_MAX_UDP]; cur < end; ++cur) {
    if ((cur != udpBlk) && (cur->localPort == localPort)) {
      return NET_ERR_PORT_USED;
    }
  }

  udpBlk->localPort = localPort;
  return NET_ERROR_OK;
}

// 计算添加伪首部的校验和
uint16_t checksumPseudo(const IpAddr *srcIp,  // 源 ip
                        const IpAddr *destIp, // 目的 ip
                        uint8_t protocol,     // 协议号
                        uint16_t *buf,        // udp 数据包
                        uint16_t size) {      // udp 数据包大小
  // 将 1 个字节的填充和 15 个字节的协议号整合到 2 字节数组中
  uint16_t zeroProtocol[] = { 0, protocol };
  // 大端表示的 udp 包长度
  uint16_t udpLen = solveEndian16(size);

  // 先计算伪首部累加和
  uint32_t sum = checksum16((uint16_t *)srcIp->array, NET_IPV4_ADDR_SIZE, 0, 0);
  sum = checksum16((uint16_t *)destIp->array, NET_IPV4_ADDR_SIZE, sum, 0);
  sum = checksum16((uint16_t *)zeroProtocol, 2, sum, 0);
  sum = checksum16((uint16_t *)&udpLen, 2, sum, 0);

  // 再将伪首部累加和与 udp 数据包累加和相加、取反
  return checksum16(buf, size, sum, 1);
}

void parseRecvedUdpPacket(UdpBlk *udp, IpAddr *srcIp, NetPacket *packet) {
  printf("===parseRecvedUdpPacket===\n");
  UdpHdr *udpHdr = (UdpHdr *)packet->data;
  uint16_t preChecksum;

  if ((packet->size) < sizeof(UdpHdr) || (packet->size < solveEndian16(udpHdr->totalLen))) {
    return;
  }

  preChecksum = udpHdr->pseudoChecksum;
  udpHdr->pseudoChecksum = 0;
  // 如果发送方将校验和设置为 0 就跳过
  if (udpHdr->pseudoChecksum != 0) {
    uint16_t checksum = checksumPseudo(srcIp,
                                      &netifIpAddr,
                                      NET_PROTOCOL_UDP,
                                      (uint16_t *)udpHdr,
                                      solveEndian16(udpHdr->totalLen));
    checksum = (checksum == 0) ? 0xFFFF : checksum;
    if (checksum != preChecksum) {
      return;
    }
  }

  // 移除 udp 包头，将 udp 数据部分交给 handler 处理
  uint16_t srcPort = solveEndian16(udpHdr->srcPort);
  if (udp->handler) {
    udp->handler(udp, srcIp, srcPort, packet);
  }
}

void initNet(void) {
  initEthernet();
  initArp();
  initIp();
  initIcmp();
  initUpd();
}

void queryNet(void) {
  queryEtherNet();
  queryArpEntry();
}
