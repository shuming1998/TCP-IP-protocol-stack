#include "datatime_server.h"
#include <string.h>
#include <time.h>

#define TIME_STR_SIZE 128   // 字符串大小

NetErr datatimeHandler(UdpBlk *udp, IpAddr *srcIp, uint16_t srcPort, NetPacket *packet) {
  time_t rawTime;
  const struct tm *timeInfo;
  NetPacket *tsPacket = netPacketAllocForSend(TIME_STR_SIZE);

  time(&rawTime);
  timeInfo = localtime(&rawTime);
  size_t strSize = strftime((char *)packet->data, TIME_STR_SIZE, "%A, %B, %d, %Y %T-%z", timeInfo);


  // 发送

  return NET_ERROR_OK;
}

NetErr createDatatimeServer(uint16_t port) {
  UdpBlk *udp = getUdpBlk(datatimeHandler);
  bindUdpBlk(udp, port);

  return NET_ERROR_OK;
}