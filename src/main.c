#include "net_data.h"
#include "datatime_server.h"
#include <stdio.h>

#define DATATIME_SERVER_PORT 13


int main() {
  initNet();
  printf("init net success!\n");

  createDatatimeServer(DATATIME_SERVER_PORT);

  printf("net running...\n");
  while (1) {
    queryNet();
  }

  return 0;
}
