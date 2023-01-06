#ifndef PCAP_DRIVER_H
#define PCAP_DRIVER_H

#include <pcap.h>
#include <stdint.h>

// 主-次版本号
#define NPCAP_VERSION_M 0
#define NPCAP_VERSION_N 9986

typedef void (* irq_handler_t)(void* arg, uint8_t isRx, const uint8_t* data, uint32_t size);

pcap_t *pcapDeviceOpen(const char* ip, const uint8_t *macAddr, uint8_t pollMode);
void pcapDeviceClose(pcap_t* pcap);
uint32_t pcapDeviceSend(pcap_t *pcap, const uint8_t *buffer, uint32_t length);
uint32_t pcapDeviceRead(pcap_t *pcap, uint8_t *buffer, uint32_t length);

#endif //PCAP_DRIVER_H
