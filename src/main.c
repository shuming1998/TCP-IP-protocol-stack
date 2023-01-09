#include "net_data.h"
#include <stdio.h>

int main() {
  initNet();
  printf("init net success!\n");
  printf("net running...\n");
  while (1) {
    queryNet();
  }

  return 0;
}
