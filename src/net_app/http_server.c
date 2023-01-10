#include "http_server.h"
#include <stdio.h>

static uint8_t buffer[1024];

// http 回调函数
static NetErr httpHandler(TcpBlk *tcp, TcpConnState event) {
  if(event == TCP_CONN_CONNECTED) {
    printf("http connected!\n");
  } else if (event == TCP_CONN_DATA_RECV) {
    uint8_t *data = buffer;
    uint16_t readSize = readDataFromTcp(tcp, buffer, sizeof(buffer));
    while (readSize) {
      uint16_t curSize = sendDataToTcp(tcp, data, readSize);
      data += curSize;
      readSize -= curSize;
    }
  } else if (event == TCP_CONN_CLOSED) {
    printf("http closed!\n");
  }
  return NET_ERROR_OK;
}

// 创建 http 服务器
NetErr createHttpServer(uint16_t port) {
  TcpBlk *tcp = getTcpBlk(httpHandler);

  bindTcpBlk(tcp, port);
  listenTcpBlk(tcp);

  return NET_ERROR_OK;
}