#include "net_data.h"
#include "http_server.h"
#include "datatime_server.h"
#include <stdio.h>

#define DATATIME_SERVER_PORT 13
#define HTTP_SERVER_PORT 80

int main() {
  initNet();
  printf("init net success!\n");

  createDatatimeServer(DATATIME_SERVER_PORT);
  createHttpServer(HTTP_SERVER_PORT);

  printf("net running...\n");
  while (1) {
    queryNet();
    solveHttpQueue();
  }

  return 0;
}
