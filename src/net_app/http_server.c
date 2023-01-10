#include "http_server.h"
#include <string.h>
#include <stdio.h>

#define TCP_FIFO_SIZE 60

typedef struct HttpQueue {
  TcpBlk *buffer[TCP_FIFO_SIZE];
  uint8_t front, tail, count;
}HttpQueue;

static char recvBuffer[1024];
static char sendBuffer[1024];
static char url[255], filePath[255];;

static HttpQueue httpQueue;

static void initHttpQueue(HttpQueue *queue) {
  queue->count = 0;
  queue->front = queue->tail = 0;
}

static NetErr HttpQueueIn(HttpQueue *queue, TcpBlk *tcp) {
  if (queue->count >= TCP_FIFO_SIZE) {
    return NET_ERR_MEM;
  }

  queue->buffer[queue->front++] = tcp;
  if (queue->front >= TCP_FIFO_SIZE) {
    queue->front = 0;
  }

  queue->count++;
  return NET_ERROR_OK;
}

static TcpBlk *HttpQueueOut(HttpQueue *queue) {
  TcpBlk *tcp;

  if (queue->count == 0) {
    return (TcpBlk *)0;
  }

  tcp = queue->buffer[queue->tail++];
  if (queue->tail >= TCP_FIFO_SIZE) {
    queue->tail = 0;
  }

  queue->count--;
  return tcp;
}

static int httpSend(TcpBlk *tcp, char *buf, int size) {
  int sendSize = 0;

  while (size > 0) {
    int currSize = sendDataToTcp(tcp, (uint8_t*)buf, (uint16_t)size);
    if (currSize < 0) break;
    size -= currSize;
    buf += currSize;
    sendSize += currSize;
    queryNet();
  }

  return sendSize;
}

static void send404NotFound(TcpBlk *tcp) {
    sprintf(sendBuffer, "HTTP/1.0 404 NOT FOUND\r\n""\r\n");
    httpSend(tcp, sendBuffer, strlen(sendBuffer));
}

static void sendFile(TcpBlk *tcp, const char *url) {
  FILE * file;
  uint32_t size;
  const char * contentType = "text/html";
  int i;

  while (*url == '/') url++;
  sprintf(filePath, "%s/%s", HTTP_DOC_PATH, url);

  file = fopen(filePath, "rb");
  if (file == NULL) {
      send404NotFound(tcp);
      return;
  }

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  fseek(file, 0, SEEK_SET);
  sprintf(sendBuffer,
          "HTTP/1.0 200 OK\r\n"
          "Content-Length:%d\r\n\r\n",
          (int)size);
  httpSend(tcp, sendBuffer, strlen(sendBuffer));

  while (!feof(file)) {
    size = fread(sendBuffer, 1, sizeof(sendBuffer), file);
    if (httpSend(tcp, sendBuffer, size) <= 0) {
      fclose(file);
      return;
    }
  }
  fclose(file);
}

// http 回调函数
static NetErr httpHandler(TcpBlk *tcp, TcpConnState event) {
  if(event == TCP_CONN_CONNECTED) {
    printf("http connected!\n");
    HttpQueueIn(&httpQueue, tcp);
  } else if (event == TCP_CONN_CLOSED) {
    printf("http closed!\n");
  }

  return NET_ERROR_OK;
}

static int getLine(TcpBlk *tcp, char *buf, int size) {
  int i = 0;
  while (i < size) {
    char c;

    if (readDataFromTcp(tcp, (uint8_t *)&c, 1) > 1) {
      if ((c != '\r') && (c != '\n')) {
        buf[i++] = c;
      } else if (c == '\n') {
        break;
      }
    }
  }
  buf[i] = '\0';
  return i;
}

static void closeHttp(TcpBlk *tcp) {
  printf("http closed\n");
  closeTcp(tcp);
}

NetErr createHttpServer(uint16_t port) {
  TcpBlk *tcp = getTcpBlk(httpHandler);

  bindTcpBlk(tcp, port);
  listenTcpBlk(tcp);
  initHttpQueue(&httpQueue);

  return NET_ERROR_OK;
}

void solveHttpQueue(void) {
  TcpBlk *tcp;

  while ((tcp = HttpQueueOut(&httpQueue)) != (TcpBlk *)0) {
    int i;
    char *temp = recvBuffer;

    if (getLine(tcp, recvBuffer, sizeof(recvBuffer)) < 0) {
      closeHttp(tcp);
      continue;
    }

    // 只处理 Get 方法
    if (strncmp(recvBuffer, "GET", 3) != 0) {
      closeHttp(tcp);
      continue;
    }

    // 读取路径
    // 跳过 GET
    while (*temp != ' ') { ++temp; }
    // 跳过空格
    while (*temp == ' ') { ++temp; }
    for (i = 0; i < sizeof(url); ++i) {
      if (*temp == ' ') { break; }
      url[i] = *temp++;
    }

    url[i] = '\0';
    if (url[strlen(url) - 1] == '/') {
        strcat(url, "index.html");
    }
    if (url[strlen(url) - 1] == '/') {
      strcat(url, "index.html");
    }

    // 发送文件
    sendFile(tcp, url);
    // 关掉服务器
    closeHttp(tcp);
  }
}