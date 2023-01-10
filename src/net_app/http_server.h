#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "net_data.h"

#define HTTP_DOC_PATH "../htdocs"

// 创建 http 服务器
NetErr createHttpServer(uint16_t port);
// 处理 http 请求
void solveHttpQueue(void);

#endif