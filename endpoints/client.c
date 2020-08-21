#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "common.h"

static char buf[4096];

int main(void)
{
  int sockfd;
  struct sockaddr_in server_addr;
  ssize_t bytes = TRANSFER_SIZE;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(8080);
  if (inet_pton(AF_INET, "10.0.1.2", &server_addr.sin_addr) != 1) {
    perror("inet_pton");
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
    perror("connect");
    return -1;
  }

  while (bytes > 0)
  {
    if (recv(sockfd, buf, sizeof(buf), MSG_WAITALL) != sizeof(buf)) {
      perror("recv");
      return -1;
    }
    bytes -= sizeof(buf);
    if (!(bytes & ((1 << 20) - 1)))
      printf("%d MiB remaining...\n", (int)(bytes >> 20));
  }

  close(sockfd);

  return 0;
}
