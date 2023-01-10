#include "net_data.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) > (b) ? (b) : (a))
#define getTcpInitSeq() ((rand() << 16) + rand()) // 生成 32 位的随机数： 高 16 位 + 低 16 位
#define convertOrder16(num) ((((num) & 0XFF) << 8) | (((num) >> 8) & 0xFF))
#define ipAddrIsEqualBuf(addr, buf) (memcmp((addr)->array, (buf), NET_IPV4_ADDR_SIZE) == 0)
#define ipAddrIsEqual(addrLhs, addrRhs) ((addrLhs)->addr == (addrRhs)->addr)
#define getIpFromBuf(dest, buf) ((dest)->addr = *(uint32_t *)(buf))

// 16 字节本地字节序转网络字节序
uint16_t solveEndian16(uint16_t v) {
	uint16_t a = 0x1234;
	char b =  *(char *)&a;
	if(b == 0x34) {
		return convertOrder16(v);
	}
  return v;
}

// 32 字节本地字节序转网络字节序
uint32_t solveEndian32(uint32_t v) {
	uint16_t a = 0x1234;
	char b =  *(char *)&a;

	if(b == 0x34) {
    uint32_t r_v;
    uint8_t* src = (uint8_t*)&v;
    uint8_t* dest = (uint8_t*)&r_v;

    dest[0] = src[3];
    dest[1] = src[2];
    dest[2] = src[1];
    dest[3] = src[0];

    return r_v;
  }

  return v;
}

// 协议栈虚拟网卡 ip 地址
static const IpAddr netifIpAddr = NET_CFG_NETIF_IP;
// 无回报 ARP 广播地址
static const uint8_t bcastEther[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t netifMac[NET_MAC_ADDR_SIZE];     // Network Interface Card Mac 地址

static NetPacket sendPacket;                    // 接收缓冲
static NetPacket recvPacket;                    // 发送缓冲
static ArpEntry arpEntry;                       // arp 单表项
static net_time_t  arpTimer;                    // arp 定时查询时间
static UdpBlk udpSocket[UDP_CFG_MAX_UDP];       // udp 控制块
static TcpBlk tcpSocket[TCP_CFG_MAX_TCP];       // tcp 控制块

const net_time_t getNetRunsTime(void) {
  return (net_time_t)(clock() / CLOCKS_PER_SEC);
}

//  根据接收到的 arp 响应包，更新 arp 表项
static void updateArpEntry(uint8_t *senderIp, uint8_t *senderMac);

// 将数据包的大小截断至指定 size
void truncatePacket(NetPacket *packet, uint16_t size) {
  packet->size = min(packet->size, size);
}

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

  if (((err = arpResolve(destIp, &macAddr)) == NET_ERROR_OK)) {
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
      parseRecvedArpPacket(packet);     // 解析 arp 包
      break;
    case NET_PROTOCOL_IP: {
      printf("NET_PROTOCOL_IP\n");
      IpHdr *ipHdr = (IpHdr *)(packet->data + sizeof(EtherHdr));
      updateArpEntry(ipHdr->srcIp, etherHdr->srcMac);
      rmHdr(packet, sizeof(EtherHdr));  // 移除以太网包头
      parseRecvedIpPacket(packet);      // 解析 ip 包
      break;
    }
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

static void updateArpEntry(uint8_t *senderIp, uint8_t *senderMac) {
  printf("updateArpEntry!\n");
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
    // printf("time to query arp: %d\n", arpTimer);
    switch (arpEntry.state) {
      // case ARP_ENTRY_FREE:
      //   uint8_t senderIp[NET_IPV4_ADDR_SIZE] = {192, 168, 1, 7};
      //   memcpy(arpEntry.ipAddr.array, senderIp, NET_IPV4_ADDR_SIZE);
      //   arpMakeRequest(&arpEntry.ipAddr);
      //   arpEntry.state = ARP_ENTRY_OK;
      //   arpEntry.ttl = ARP_CFG_ENTRY_PENDING_TTL;
      //   arpEntry.retryCnt = ARP_CFG_MAX_RETRY_TIMES;
      //   break;
      case ARP_ENTRY_OK:
        if (--arpEntry.ttl == 0) {
          printf("ARP OK: arpEntry.ttl: 0\n");
          arpMakeRequest(&arpEntry.ipAddr);         // arp 表项超时，重新获取该超时的 arp 表项
          arpEntry.state = ARP_ENTRY_PENDING;       // 更新 arp 表项状态为：正在查询
          arpEntry.ttl = ARP_CFG_ENTRY_PENDING_TTL; // 设置 PENDING 状态的 arp 表项响应包的超时时间
        }
        break;
      case ARP_ENTRY_PENDING:
        if (--arpEntry.ttl == 0) {                  // 判断 PENDING 状态 arp 包的响应时间是否超时
          printf("ARP_ENTRY_PENDING: arpEntry.ttl: %d!\n", arpEntry.ttl);
          if (arpEntry.retryCnt-- == 0) {           // 响应时间超时，并且重试次数为 0，直接 free 表项
            printf("ARP PENDING: ttl: 0 & retryCnt: %d\n", arpEntry.retryCnt);
            arpEntry.state = ARP_ENTRY_FREE;
          } else {                                  // 响应事件超时，且剩余请求次数，尝试重新获取 arp 响应包
            printf("ARP PENDING: ttl: 0 & retryCnt: %d\n", arpEntry.retryCnt);
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
          truncatePacket(packet, totalSize);
          // 移除 udp 包头
          rmHdr(packet, hdrSize);
          // 处理 udp 数据包
          parseRecvedUdpPacket(udp, &srcIp, packet);
        } else {
          destIcmpUnreach(ICMP_CODE_PORT_UNREACHABLE, ipHdr);
        }
      }
      break;
    case NET_PROTOCOL_TCP:
      printf("NET_PROTOCOL_TCP\n");
      // 不含数据的 TCP 包： EtherHdr(14) + IpHdr(20) + TcpHdr(20) = 54
      // 以太网规范：最小包 >= 14 + 46 = 60 ，为了避免填充的 6 字节带来的影响(如校验和)，需要将其截断
      truncatePacket(packet, totalSize);
      rmHdr(packet, hdrSize);
      parseRecvedTcpPacket(&srcIp, packet);
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
  icmpReplyHdr->seq = icmpHdr->seq;\
  icmpReplyHdr->checksum = 0;
  // 拷贝 icmp 数据段
  memcpy(((uint8_t *)icmpReplyHdr) + sizeof(IcmpHdr),
        ((uint8_t *)icmpHdr) + sizeof(IcmpHdr),
        packet->size - sizeof(IcmpHdr));
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
  IcmpHdr *icmpHdr;
  IpAddr destIp;
  NetPacket *packet;

  // 计算 icmp 不可达报文长度
  uint16_t ipHdrSize = ipHdr->hdrLen * 4;
  uint16_t ipDataSize = solveEndian16(ipHdr->totalLen) - ipHdrSize;
  ipDataSize = ipHdrSize + ipDataSize;
  // ipDataSize = ipHdrSize + min(ipDataSize, ICMP_DATA_ORIGINAL);

  packet = netPacketAllocForSend(sizeof(IcmpHdr) + ipDataSize);
  icmpHdr = (IcmpHdr *)packet->data;
  icmpHdr->type = ICMP_TYPE_UNREACHABLE;
  icmpHdr->code = code;
  icmpHdr->id = 0;   // unused
  icmpHdr->seq = 0;  // unused
  // 拷贝 icmp 数据段到 ipmp 头部后面
  memcpy(((uint8_t *)icmpHdr) + sizeof(IcmpHdr), ipHdr, ipDataSize);
  icmpHdr->checksum = 0;
  icmpHdr->checksum = checksum16((uint16_t *)icmpHdr, packet->size, 0, 1);

  getIpFromBuf(&destIp, ipHdr->srcIp);

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

void freeUdpBlk(UdpBlk *udp) {
  udp->state = UDP_STATE_FREE;
}

UdpBlk *findUdpBlk(uint16_t port) {
  UdpBlk *cur, *end;

  for (cur = udpSocket, end = &udpSocket[UDP_CFG_MAX_UDP]; cur < end; ++cur) {
    if ((cur->state != UDP_STATE_FREE) && (cur->localPort == port)) {
      return cur;
    }
  }

  return (UdpBlk *)0;
}

NetErr bindUdpBlk(UdpBlk *udp, uint16_t localPort) {
  UdpBlk *cur, *end;
  // 0 号端口有特定用途
  if (localPort == 0) {
    return NET_ERR_PORT_OCCUPIED;
  }

  for (cur = udpSocket, end = &udpSocket[UDP_CFG_MAX_UDP]; cur < end; ++cur) {
    if ((cur != udp) && (cur->localPort == localPort)) {
      return NET_ERR_PORT_USED;
    }
  }

  udp->localPort = localPort;
  return NET_ERROR_OK;
}

// 计算添加伪首部的校验和
uint16_t checksumPseudo(const IpAddr *srcIp,  // 源 ip
                        const IpAddr *destIp, // 目的 ip
                        uint8_t protocol,     // 协议号
                        uint16_t *buf,        // udp 数据包
                        uint16_t size) {      // udp 数据包大小
  // 将 1 个字节的填充和 15 个字节的协议号整合到 2 字节数组中
  uint16_t zeroProtocol[2] = { 0, protocol };
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

  if ((packet->size < sizeof(UdpHdr)) || (packet->size < solveEndian16(udpHdr->totalLen))) {
    return;
  }

  preChecksum = udpHdr->pseudoChecksum;
  udpHdr->pseudoChecksum = 0;
  // 如果发送方将校验和设置为 0 就跳过
  if (preChecksum != 0) {
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
  rmHdr(packet, sizeof(UdpHdr));

  if (udp->handler) {
    udp->handler(udp, srcIp, srcPort, packet);
  }
}

NetErr sendUdpTo(UdpBlk *udp, IpAddr *destIp, uint16_t destPort, NetPacket *packet) {
  UdpHdr *udpHdr;
  uint16_t pseudoChecksum;

  addHdr(packet, sizeof(UdpHdr));
  udpHdr = (UdpHdr *)packet->data;
  udpHdr->srcPort = solveEndian16(udp->localPort);
  udpHdr->destPort = solveEndian16(destPort);
  udpHdr->totalLen = solveEndian16(packet->size);
  udpHdr->pseudoChecksum = 0;
  pseudoChecksum = checksumPseudo(&netifIpAddr,
                                  destIp,
                                  NET_PROTOCOL_UDP,
                                  (uint16_t *)packet->data,
                                  packet->size);
  udpHdr->pseudoChecksum = (pseudoChecksum == 0) ? 0xFFFF : pseudoChecksum;

  return sendIpPacketTo(NET_PROTOCOL_UDP, destIp, packet);
}

// 分配空闲的 tcp 控制块
static TcpBlk *allocTcpBlk(void) {
  TcpBlk *tcp, *end;

  for (tcp = tcpSocket, end = tcpSocket + TCP_CFG_MAX_TCP; tcp < end; ++tcp) {
    if (tcp->state == TCP_STATE_FREE) {
      tcp->state = TCP_STATE_CLOSED;
      tcp->localPort = 0;
      tcp->remotePort = 0;
      tcp->remoreIp.addr = 0;
      tcp->nextSeq = getTcpInitSeq();
      tcp->ack = 0;
      tcp->remoteMss = TCP_MSS_DEFAULT;
      tcp->remoteWin = TCP_MSS_DEFAULT;
      tcp->handler = (tcpHandler)0;
      return tcp;
    }
  }

  return (TcpBlk *)0;
}

// 释放 tcp 控制块
static void freeTcp(TcpBlk *tcp) {
  tcp->state = TCP_STATE_FREE;
}

// 查找 tcp 控制块
static TcpBlk *findTcpBlk(IpAddr *remoteIp, uint16_t remotePort, uint16_t localPort) {
  TcpBlk *tcp, *end;
  TcpBlk *listen = (TcpBlk *)0;

  for (tcp = tcpSocket, end = tcpSocket + TCP_CFG_MAX_TCP; tcp < end; ++tcp) {
    if ((tcp->state == TCP_STATE_FREE) || (tcp->localPort != localPort)) {
      continue;
    }

    if (ipAddrIsEqual(remoteIp, &tcp->remoreIp) && (remotePort == tcp->remotePort)) {
      return tcp;
    }

    // 没找到指定的 tcp 控制块，但找到了 liste 状态的，也返回
    if (tcp->state == TCP_STATE_LISTEN) {
      listen = tcp;
    }
  }

  return listen;
}

void initTcp() {
  memset(tcpSocket, 0, sizeof(tcpSocket));
}

// 发送 tcp 复位包报告错误
static NetErr sendResetTcpPacket(uint32_t remoteAck,
                                 uint16_t localPort,
                                 IpAddr *remoteIp,
                                 uint16_t remotePort) {
  NetPacket *packet = netPacketAllocForSend(sizeof(TcpHdr));
  TcpHdr *tcpHdr = (TcpHdr *)packet->data;

  tcpHdr->srcPort = solveEndian16(localPort);
  tcpHdr->destPort = solveEndian16(remotePort);
  tcpHdr->seq = 0;
  tcpHdr->ack = solveEndian32(remoteAck);
  tcpHdr->hdrFlags.all = 0;
  tcpHdr->hdrFlags.hdrLen = sizeof(TcpHdr) / 4;
  tcpHdr->hdrFlags.flags = TCP_FLAG_RST | TCP_FLAG_ACK;
  tcpHdr->hdrFlags.all = solveEndian16(tcpHdr->hdrFlags.all);
  tcpHdr->window = 0;
  tcpHdr->pseudoChecksum = 0;
  tcpHdr->urgentPtr = 0;
  tcpHdr->pseudoChecksum = checksumPseudo(&netifIpAddr,
                                          remoteIp,
                                          NET_PROTOCOL_TCP,
                                          (uint16_t *)packet->data,
                                          packet->size);
  tcpHdr->pseudoChecksum = (tcpHdr->pseudoChecksum == 0) ? 0xFFFF : tcpHdr->pseudoChecksum;

  return sendIpPacketTo(NET_PROTOCOL_TCP, remoteIp, packet);
}

static NetErr sendTcpTo(TcpBlk *tcp, uint8_t flags) {
  NetPacket *packet;
  TcpHdr *tcpHdr;
  NetErr err;
  uint16_t optSize = (flags & TCP_FLAG_SYN) ? 4 : 0;

  packet = netPacketAllocForSend(sizeof(TcpHdr) + optSize);
  tcpHdr = (TcpHdr *)packet->data;
  tcpHdr->srcPort = solveEndian16(tcp->localPort);
  tcpHdr->destPort = solveEndian16(tcp->remotePort);
  tcpHdr->seq = solveEndian32(tcp->nextSeq);
  tcpHdr->ack = solveEndian32(tcp->ack);
  tcpHdr->hdrFlags.all = 0;
  tcpHdr->hdrFlags.hdrLen = (optSize + sizeof(TcpHdr)) / 4;
  tcpHdr->hdrFlags.flags = flags;
  tcpHdr->hdrFlags.all = solveEndian16(tcpHdr->hdrFlags.all);
  tcpHdr->window = 1024;
  tcpHdr->pseudoChecksum = 0;
  tcpHdr->urgentPtr = 0;
  if (flags & TCP_FLAG_SYN) {
    // 写入附加数据
    uint8_t *optData = packet->data + sizeof(TcpHdr);
    optData[0] = TCP_KIND_MSS;
    optData[1] = 4;
    *(uint16_t *)(optData + 2) = solveEndian16(TCP_MSS_DEFAULT);
  }
  tcpHdr->pseudoChecksum = checksumPseudo(&netifIpAddr,
                                          &tcp->remoreIp,
                                          NET_PROTOCOL_TCP,
                                          (uint16_t *)packet->data,
                                          packet->size);
  tcpHdr->pseudoChecksum = (tcpHdr->pseudoChecksum == 0) ? 0xFFFF : tcpHdr->pseudoChecksum;

  err = sendIpPacketTo(NET_PROTOCOL_TCP, &tcp->remoreIp, packet);
  if (err < 0) {
    return err;
  }

  // 发送完毕后，调整 tcp 头部中的数据
  // tcp->remoteWin -=
  if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)) {
    // FIN 占用一个序号
    tcp->nextSeq++;
  }

  return NET_ERROR_OK;
}

// 将 tcp 头部中的选项数据 mss 读取到 tcp 控制块的 remoteMss 中
static void readTcpMss(TcpBlk *tcp, TcpHdr *tcpHdr) {
  uint16_t optLen = tcpHdr->hdrFlags.hdrLen * 4 - sizeof(TcpHdr);

  // 如果对方没有发送选项数据，设置一个默认值
  if (0 == optLen) {
    tcp->remoteMss = TCP_MSS_DEFAULT;
  } else {
    uint8_t *optData = (uint8_t *)tcpHdr + sizeof(TcpHdr);
    uint8_t *optDataEnd = optData + optLen;

    while ((*optData != TCP_KIND_END) && (optData < optDataEnd)) {
      if ((*optData++ == TCP_KIND_MSS) && (*optData++ == 4)) {
        tcp->remoteMss = solveEndian16(*(uint16_t *)optData);
        return;
      }
    }
  }
}

// 根据监听状态的 tcp 控制块，创建用于处理连接请求的 tcp 控制块
static void acceptTcpProcess(TcpBlk *listenTcp, IpAddr *remoteIp, TcpHdr *tcpHdr) {
  uint16_t hdrFlgs = tcpHdr->hdrFlags.all;

  // 判断是否为第一次握手
  if (hdrFlgs & TCP_FLAG_SYN) {
    printf("第一次握手!\n");
    NetErr err;
    uint32_t ack = tcpHdr->seq + 1;

    TcpBlk *newTcp = allocTcpBlk();
    if (!newTcp) {
      return;
    }

    // 状态为：已收到 syn，即将发送 syn + ack
    newTcp->state = TCP_STATE_SYN_RCVD;
    newTcp->localPort = listenTcp->localPort;
    newTcp->handler = listenTcp->handler;
    newTcp->remotePort = tcpHdr->srcPort;
    newTcp->remoreIp.addr = remoteIp->addr;
    newTcp->ack = ack;                        // 希望对方下次发来的序号
    newTcp->nextSeq = getTcpInitSeq();        // 设置初始序号
    newTcp->remoteWin = tcpHdr->window;
    readTcpMss(newTcp, tcpHdr);               // 读取对方选项数据中的 mss 值

    // 动作： 发送 syn + ack 报文
    err = sendTcpTo(newTcp, TCP_FLAG_SYN | TCP_FLAG_ACK);
    if (err < 0) {
      closeTcp(newTcp);
      return;
    }
  } else {
    sendResetTcpPacket(tcpHdr->seq, listenTcp->localPort, remoteIp, tcpHdr->srcPort);
  }
}

void parseRecvedTcpPacket(IpAddr *remoteIp, NetPacket *packet) {
  printf("parseRecvedTcpPacket!\n");
  TcpHdr *tcpHdr = (TcpHdr *)packet->data;
  TcpBlk *tcp;
  uint16_t preChecksum;

  if (packet->size < sizeof(TcpHdr)) {
    return;
  }

  // 计算伪校验和
  preChecksum = tcpHdr->pseudoChecksum;
  tcpHdr->pseudoChecksum = 0;
  // 如果发送方将校验和设置为 0 就跳过
  if (preChecksum != 0) {
    uint16_t checksum = checksumPseudo(remoteIp,
                                      &netifIpAddr,
                                      NET_PROTOCOL_TCP,
                                      (uint16_t *)tcpHdr,
                                      packet->size);
    checksum = (checksum == 0) ? 0xFFFF : checksum;
    if (checksum != preChecksum) {
      return;
    }
  }

  // 提前对 tcp 头部数据进行大小端转换
  tcpHdr->srcPort = solveEndian16(tcpHdr->srcPort);
  tcpHdr->destPort = solveEndian16(tcpHdr->destPort);
  tcpHdr->hdrFlags.all = solveEndian16(tcpHdr->hdrFlags.all);
  tcpHdr->seq = solveEndian32(tcpHdr->seq);
  tcpHdr->ack = solveEndian32(tcpHdr->ack);
  tcpHdr->window = solveEndian16(tcpHdr->window);

  tcp = findTcpBlk(remoteIp, tcpHdr->srcPort, tcpHdr->destPort);
  if (tcp == (TcpBlk *)0) {
    printf("sendResetTcpPacket!\n");
    sendResetTcpPacket(tcpHdr->seq + 1, tcpHdr->destPort, remoteIp, tcpHdr->srcPort);
    return;
  }

  tcp->remoteWin = tcpHdr->window;

  if (tcp->state == TCP_STATE_LISTEN) {
    // 处理接收的 tcp 报文，创建并发送回应 tcp 报文
    acceptTcpProcess(tcp, remoteIp, tcpHdr);
    return;
  }

  // 收到 syn + ack 报文，处理即将发送的第三次握手的 ack 报文
  // 如果报文不是自己想要的，直接发送重置报文
  if (tcpHdr->seq != tcp->ack) {
    sendResetTcpPacket(tcpHdr->seq + 1, tcpHdr->destPort, remoteIp, tcpHdr->srcPort);
    return;
  }

  // 收到自己想要的报文，先移除包头
  rmHdr(packet, tcpHdr->hdrFlags.hdrLen);
  // 进入状态机
  switch (tcp->state) {
    // 收到第二次握手的报文
    case TCP_STATE_SYN_RCVD:
      if (tcpHdr->hdrFlags.flags & TCP_FLAG_ACK) {
        tcp->state = TCP_STATE_ESTABLISHED;
        tcp->handler(tcp, TCP_CONN_CONNECTED);
      }
      break;
    // 已建立连接，可以处理数据包
    case TCP_STATE_ESTABLISHED:
      if (tcpHdr->hdrFlags.flags & TCP_FLAG_FIN) {
        // 如果收到客户端主动关闭放发来的报文，服务器直接发送 FIN + ACK，跳过 CLOSE-WAIT 直接进入 LAST-ACK
        tcp->state = TCP_STATE_LAST_ACK;
        tcp->ack++; // FIN 标志位占一个序号
        sendTcpTo(tcp, TCP_FLAG_FIN | TCP_FLAG_ACK);
      }
      break;
    case TCP_STATE_FIN_WAIT_1:
      // 判断收到的包是否为 FIN 和 ACK 同时置位
      if ((tcpHdr->hdrFlags.flags & (TCP_FLAG_FIN | TCP_FLAG_ACK)) == (TCP_FLAG_FIN | TCP_FLAG_ACK)) {
        // 本应进入 timewait 状态，等待 2msl，这里直接释放
        closeTcp(tcp);
      } else if (tcpHdr->hdrFlags.flags & TCP_FLAG_ACK) {
        // 只收到了 ACK，从 FIN_WAIT_1 转为 FIN_WAIT_2
        tcp->state = TCP_STATE_FIN_WAIT_2;
      }
      break;
    case TCP_STATE_FIN_WAIT_2:
      if (tcpHdr->hdrFlags.flags & TCP_FLAG_FIN) {
        tcp->ack++; // FIN 标志位占一个序号
        sendTcpTo(tcp, TCP_FLAG_ACK);
        closeTcp(tcp);
      }
      break;
    case TCP_STATE_LAST_ACK:
      if (tcpHdr->hdrFlags.flags & TCP_FLAG_ACK) {
        tcp->handler(tcp, TCP_CONN_CLOSED);
        closeTcp(tcp);
      }
      break;
  }
}

TcpBlk *getTcpBlk(tcpHandler handler) {
  TcpBlk *tcp = allocTcpBlk();

  if (!tcp) {
    return (TcpBlk *)0;
  }

  tcp->state = TCP_STATE_CLOSED;
  tcp->handler = handler;

  return tcp;
}

NetErr bindTcpBlk(TcpBlk *tcp, uint16_t localPort) {
  TcpBlk *cur, *end;

  for (cur = tcpSocket, end = &tcpSocket[TCP_CFG_MAX_TCP]; cur < end; ++cur) {
    if ((cur != tcp) && (cur->localPort == localPort)) {
      return NET_ERR_PORT_USED;
    }
  }
  tcp->localPort = localPort;

  return NET_ERROR_OK;
}

NetErr listenTcpBlk(TcpBlk *tcp) {
  tcp->state = TCP_STATE_LISTEN;

  return NET_ERROR_OK;
}

NetErr closeTcp(TcpBlk *tcp) {
  NetErr err;

  if (tcp->state == TCP_STATE_ESTABLISHED) {
    err = sendTcpTo(tcp, TCP_FLAG_FIN | TCP_FLAG_ACK);
    if (err < 0) {
      return err;
    }
    tcp->state = TCP_STATE_FIN_WAIT_1;
  } else {
    freeTcp(tcp);
  }

  return NET_ERROR_OK;
}

void initNet(void) {
  initEthernet();
  initArp();
  initIp();
  initIcmp();
  initUpd();
  initTcp();
  srand(getNetRunsTime());
}

void queryNet(void) {
  queryEtherNet();
  queryArpEntry();
}
