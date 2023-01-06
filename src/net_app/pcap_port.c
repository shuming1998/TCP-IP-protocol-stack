#include "net_data.h"
#include "pcap_device.h"

#include <string.h>
#include <stdlib.h>

static pcap_t *pcap;
// const char *ipStr = "127.0.0.1";
const char *ipStr = "192.168.2.101";
const char selfMacAddr[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

// 由驱动将 mac 地址写入
netErr netDriverOpen(uint8_t *macAddr) {
  memcpy(macAddr, selfMacAddr, sizeof(selfMacAddr));
  pcap = pcapDeviceOpen(ipStr, selfMacAddr, 1);
  // 判断驱动是否打开失败
  if ((pcap_t *)0 == pcap) {
    exit(-1);
  }
  return NET_ERROR_OK;
}

netErr netDriverSend(NetDataPacket *packet) {
  return pcapDeviceSend(pcap, packet->data, packet->size);
}

netErr netDriverRead(NetDataPacket **packet) {
  NetDataPacket *readPacket = netPacketAllocForRead(NET_DATA_CFG_PACKET_MAX_SIZE);
  uint16_t size = pcapDeviceRead(pcap, readPacket->data, NET_DATA_CFG_PACKET_MAX_SIZE);
  if (size > 0) {
    readPacket->size = size;
    *packet = readPacket;
    return NET_ERROR_OK;
  }
  return NET_ERROR_IO;
}