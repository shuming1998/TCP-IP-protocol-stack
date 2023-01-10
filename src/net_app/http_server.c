#include "http_server.h"
#include <stdio.h>

// http 回调函数
static NetErr httpHandler(TcpBlk *tcp, TcpConnState event) {
  if(event == TCP_CONN_CONNECTED) {
    printf("http connected!\n");
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