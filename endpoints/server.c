#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "common.h"

static char buf[4096] = "Hello, world!";

int main(void)
{
  const int on = 1;
  int sockfd, client_fd;
  struct sockaddr_in server_addr;
  struct sockaddr client_addr;
  socklen_t client_addrlen = sizeof(client_addr);
  ssize_t bytes = TRANSFER_SIZE;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket");
    return -1;
  }

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(8080);
  if (inet_pton(AF_INET, "0.0.0.0", &server_addr.sin_addr) != 1) {
    perror("inet_pton");
    return -1;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
    perror("setsockopt");
    return -1;
  }

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
    perror("bind");
    return -1;
  }

  if (listen(sockfd, 0) != 0) {
    perror("listen");
    return -1;
  }

  client_fd = accept(sockfd, &client_addr, &client_addrlen);
  if (client_fd < 0) {
    perror("accept");
    return -1;
  }

  while (bytes > 0)
  {
    ssize_t sz = bytes > sizeof(buf) ? sizeof(buf) : bytes;

    sz = send(client_fd, buf, sz, MSG_NOSIGNAL);
    if (sz < 0) {
      perror("send");
      return -1;
    }

    bytes -= sz;
  }

  close(client_fd);
  close(sockfd);

  return 0;
}
