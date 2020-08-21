#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "list.h"

struct packet
{
  uint64_t tx_stamp;
  uint64_t rx_stamp;
  struct list_head node;

  size_t length;
  uint8_t buffer[0];
};

struct udp_record
{
  uint64_t timestamp;
  size_t length;
};

#define CLIENT_INTERFACE "client1"
#define SERVER_INTERFACE "server1"
#define CLIENT_IP "10.0.1.3"
#define SERVER_IP "10.0.1.2"

#define PACKET_ALLOC_SIZE 2048
#define PACKET_LENGTH_MAX (PACKET_ALLOC_SIZE - sizeof(struct packet))

#define MAX_UDP_RECORDS 100000

#if RAND_MAX != (1u << 31) - 1
# error "RAND_MAX is unexpected and unsupported, please fix it manually."
#endif

enum
{
  LTE_DOWNLINK = 1,
  LTE_UPLINK   = 2,
};

static int sk_snd_client, sk_snd_server;
static int sk_rcv_client, sk_rcv_server;
static struct sockaddr_in client_addr, server_addr;

static struct list_head net_ul_list;
static struct list_head lte_ul_list, lte_dl_list;
static size_t lte_tokens;
static int lte_state;
static uint64_t lte_state_stamp;

static struct udp_record udp_records[MAX_UDP_RECORDS], *curr_udp_record;
static int64_t udp_stamp_offset;

static inline uint64_t current_timestamp(void)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    fprintf(stderr, "[Error] current_timestamp: clock_gettime failed (%s)\n",
                    strerror(errno));
    exit(EXIT_FAILURE);
  }

  return ts.tv_sec * 1000ull + ts.tv_nsec / 1000000;
}

static int sk_snd_open(const char *netdev)
{
  const int on = 1;
  int sk;
  const char *func;

  func = "socket";
  sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sk < 0)
    goto fail;

  func = "setsockopt(IP_HDRINCL)";
  if (setsockopt(sk, SOL_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    goto fail;

  func = "setsockopt(SO_BINDTODEVICE)";
  if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE, netdev, strlen(netdev)) < 0)
    goto fail;

  return sk;
fail:
  fprintf(stderr, "[Error] sk_snd_open(\"%s\"): %s failed (%s)\n",
                  netdev, func, strerror(errno));
  exit(EXIT_FAILURE);
}

static int sk_rcv_open(const char *netdev)
{
  int sk;
  struct sockaddr_ll addr;
  const char *func;

  func = "socket";
  sk = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
  if (sk < 0)
    goto fail;

  func = "bind";
  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_IP);
  addr.sll_ifindex = if_nametoindex(netdev);
  if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    goto fail;

  return sk;
fail:
  fprintf(stderr, "[Error] sk_rcv_open(\"%s\"): %s failed (%s)\n",
                  netdev, func, strerror(errno));
  exit(EXIT_FAILURE);
}

static void sk_send(int sk, struct packet *pkt, struct sockaddr_in *dest)
{
  ssize_t retval;

  retval = sendto(sk, pkt->buffer, pkt->length,
                  MSG_DONTWAIT, (struct sockaddr *)dest, sizeof(*dest));
  if (retval != pkt->length)
    fprintf(stderr, "[Warning] sk_send: sendto failed (%s), dropping...\n",
                    retval < 0 ? strerror(errno) : "Sent partially");

  free(pkt);
}

static struct packet *sk_recv(int sk)
{
  static struct packet *empty_packet = NULL;
  struct packet *pkt;
  struct sockaddr addr;
  socklen_t addrlen = sizeof(addr);
  ssize_t retval;

  pkt = empty_packet ? : malloc(PACKET_ALLOC_SIZE);
  if (!pkt) {
    fprintf(stderr, "[Warning] sk_recv: malloc failed, out of memory?\n");
    return NULL;
  }
  empty_packet = pkt;

  retval = recvfrom(sk, pkt->buffer, PACKET_LENGTH_MAX,
              MSG_DONTWAIT | MSG_TRUNC, &addr, &addrlen);
  if (retval < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return NULL;
  if (retval < 0) {
    fprintf(stderr, "[Warning] sk_recv: recvfrom failed (%s)\n",
                    strerror(errno));
    return NULL;
  }
  if (retval > PACKET_LENGTH_MAX) {
    fprintf(stderr,
        "[Warning] sk_recv: Incoming packet is too big, dropping...\n");
    return NULL;
  }
  empty_packet = NULL;

  pkt->length = retval;
  pkt->tx_stamp = current_timestamp();
  return pkt;
}

static int process_server_tx(void)
{
  struct packet *pkt;
  uint64_t ts_min, ts_max, ts_new;
  int cnt = 0;

  while ((pkt = sk_recv(sk_rcv_server)))
  {
    if (!list_empty(&lte_dl_list)) {
      struct packet *last_pkt;
      uint64_t ts_delta;
      last_pkt = list_last_entry(&lte_dl_list, struct packet, node);
      ts_delta = pkt->tx_stamp - last_pkt->tx_stamp;
  
      ts_min = last_pkt->rx_stamp + ts_delta / 2;
      ts_max = last_pkt->rx_stamp + ts_delta * 2;
    } else {
      ts_min = 0;
      ts_max = ~0ull;
    }
  
    ts_new = pkt->tx_stamp;
    ts_new += 45 + __builtin_popcount(rand() & 0x3fffffff);
    if (ts_new < ts_min)
      ts_new = ts_min;
    if (ts_new > ts_max)
      ts_new = ts_max;
    pkt->rx_stamp = ts_new;
  
    list_add_tail(&pkt->node, &lte_dl_list);
    ++cnt;
  }

  return cnt;
}

static int process_server_rx(void)
{
  uint64_t ts = current_timestamp();
  int cnt = 0;

  while (!list_empty(&net_ul_list))
  {
    struct packet *pkt;
    pkt = list_first_entry(&net_ul_list, struct packet, node);
    if (pkt->rx_stamp > ts)
      break;

    list_del(&pkt->node);
    sk_send(sk_snd_server, pkt, &server_addr);
    ++cnt;
  }

  return cnt;
}

static void drop_lte_buffer(uint64_t ts)
{
  struct packet *pkt;

  while ((pkt = list_first_entry_or_null(&lte_dl_list, struct packet, node)))
  {
    if (pkt->rx_stamp > ts)
      break;
    list_del(&pkt->node);
    free(pkt);
  }
}

static int process_lte_dl(void)
{
  uint64_t ts = current_timestamp();
  int cnt = 0;

  while (!list_empty(&lte_dl_list))
  {
    struct packet *pkt;
    pkt = list_first_entry(&lte_dl_list, struct packet, node);
    if (pkt->length > lte_tokens)
      break;
    if (pkt->rx_stamp > ts)
      break;

    lte_tokens -= pkt->length;
    list_del(&pkt->node);
    sk_send(sk_snd_client, pkt, &client_addr);
    ++cnt;
  }

  return cnt;
}

static int process_lte_ul_req(void)
{
  struct packet *pkt;
  int cnt = 0;

  while ((pkt = sk_recv(sk_rcv_client)))
  {
    list_add_tail(&pkt->node, &lte_ul_list);
    ++cnt;
  }

  return cnt;
}

static int process_lte_ul_rsp(void)
{
  uint64_t ts = current_timestamp();
  uint64_t ts_min, ts_max, ts_new;
  int cnt = 0;

  while (!list_empty(&lte_ul_list))
  {
    struct packet *pkt;
    pkt = list_first_entry(&lte_ul_list, struct packet, node);
    if (pkt->length > lte_tokens)
      break;

    lte_tokens -= pkt->length;
    list_del(&pkt->node);
    pkt->tx_stamp = ts;

    if (!list_empty(&net_ul_list)) {
      struct packet *last_pkt;
      uint64_t ts_delta;
      last_pkt = list_last_entry(&net_ul_list, struct packet, node);
      ts_delta = pkt->tx_stamp - last_pkt->tx_stamp;
  
      ts_min = last_pkt->rx_stamp + ts_delta / 2;
      ts_max = last_pkt->rx_stamp + ts_delta * 2;
    } else {
      ts_min = 0;
      ts_max = ~0ull;
    }
  
    ts_new = pkt->tx_stamp;
    ts_new += 45 + __builtin_popcount(rand() & 0x3fffffff);
    if (ts_new < ts_min)
      ts_new = ts_min;
    if (ts_new > ts_max)
      ts_new = ts_max;
    pkt->rx_stamp = ts_new;
  
    list_add_tail(&pkt->node, &net_ul_list);
    ++cnt;
  }

  return cnt;
}

static int process_lte(void)
{
  uint64_t ts, udp_ts;

  process_lte_ul_req();

  ts = current_timestamp();
  udp_ts = ts + udp_stamp_offset;
  if (!list_empty(&lte_ul_list) &&
      lte_state == LTE_DOWNLINK && !~lte_state_stamp)
    lte_state_stamp = udp_ts + 5 + (rand() % 5);
  if (udp_ts >= curr_udp_record->timestamp + 20)
    lte_tokens = 0;
  if (lte_state == LTE_UPLINK && lte_state_stamp < udp_ts) {
    lte_state = LTE_DOWNLINK;
    lte_state_stamp = ~0ull;
    lte_tokens = 0;
  }

  while (curr_udp_record[1].timestamp <= udp_ts)
  {
    struct udp_record *curr, *next;
    uint64_t ts_delta;
    curr = curr_udp_record;
    next = curr + 1;
    ts_delta = next->timestamp - curr->timestamp;

    if (ts_delta >= 100 && !(rand() & 7))
      drop_lte_buffer(next->timestamp - udp_stamp_offset);
    if (lte_state == LTE_DOWNLINK && lte_state_stamp <= next->timestamp) {
      lte_state = LTE_UPLINK;
      lte_state_stamp = next->timestamp + 1;
      lte_tokens = 0;
    }
    lte_tokens += next->length;
    curr_udp_record = next;
  }
  if (lte_tokens >= 6144)
    lte_tokens = 6144;

  return lte_state == LTE_UPLINK ? process_lte_ul_rsp() : process_lte_dl();
}

static void read_udp_records(void)
{
  const char *func, *errmsg = NULL;
  FILE *fp;
  double timestamp;
  unsigned int length;
  int retval;
  struct udp_record *record = udp_records;

  func = "fopen";
  fp = fopen("/tmp/udp/xat", "r");
  if (!fp)
    goto fail;

  func = "fscanf";
  while ((retval = fscanf(fp, " %lf,%d", &timestamp, &length)) == 2)
  {
    record->timestamp = (uint64_t)(timestamp * 1000 + 0.5);
    record->length = length;
    if (++record == &udp_records[MAX_UDP_RECORDS - 1])
      break;
  }
  if (retval == EOF && ferror(fp))
    goto fail;
  errmsg = "Matching failure";
  if (retval != EOF && retval != 2)
    goto fail;

  fclose(fp);
  record->timestamp = ~0ull;
  record->length = 0;

  return;
fail:
  fprintf(stderr, "[Error] read_udp_records: %s failed (%s)\n",
                  func, errmsg ? : strerror(errno));
  exit(EXIT_FAILURE);
}

int main(void)
{
  int retval;
  struct packet *pkt;

  srand(19260817);

  client_addr.sin_family = server_addr.sin_family = AF_INET;
  client_addr.sin_port = server_addr.sin_port = 0;
  if ((retval = inet_pton(AF_INET, CLIENT_IP, &client_addr.sin_addr)) != 1 ||
      (retval = inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr)) != 1) {
    fprintf(stderr, "[Error] main: inet_pton failed (%s)\n",
                    retval == 0 ? "Illegal address" : strerror(errno));
    return -1;
  }

  sk_rcv_client = sk_rcv_open(CLIENT_INTERFACE);
  sk_rcv_server = sk_rcv_open(SERVER_INTERFACE);
  sk_snd_client = sk_snd_open(CLIENT_INTERFACE);
  sk_snd_server = sk_snd_open(SERVER_INTERFACE);

  INIT_LIST_HEAD(&net_ul_list);
  INIT_LIST_HEAD(&lte_ul_list);
  INIT_LIST_HEAD(&lte_dl_list);

  read_udp_records();
  curr_udp_record = &udp_records[3];
  lte_state = LTE_DOWNLINK;
  lte_state_stamp = ~0ull;

  while (process_lte_ul_req() == 0)
    sched_yield();
  pkt = list_first_entry(&lte_ul_list, struct packet, node);
  udp_stamp_offset = curr_udp_record->timestamp - pkt->tx_stamp;
  process_lte();

  for (;;)
  {
    int cnt = 0;
    cnt += process_server_tx();
    cnt += process_server_rx();
    cnt += process_lte();
    if (!cnt)
      sched_yield();
  }

  return 0;
}
