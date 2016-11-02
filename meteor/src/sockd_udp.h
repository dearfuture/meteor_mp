#ifndef SOCKD_UDP_H_
#define SOCKD_UDP_H_

#include "meteor.h"
#include "sockd.h"

/* encapsulation for UDP packets. */
struct socks_udp_header_s;
typedef struct socks_udp_header_s socks_udp_header_t;
struct socks_udp_header_s
{
	unsigned char	reserved[2];
	unsigned char	frag;
	socks_host_t	host;
} ;

#define HEADERSIZE_UDP(packet) (                                               \
   sizeof((packet)->flag) + sizeof((packet)->frag)                             \
   + sizeof((packet)->host.atype) + sizeof((packet)->host.port)                \
   + (ADDRESSIZE_V5(packet)))

#define ADDRESSIZE_V5(packet) (                                                \
  (packet)->host.atype == SOCKS_ATYPE_IPV4 ?                                    \
        sizeof((packet)->host.addr.ipv4)                                       \
      : (packet)->host.atype  == (unsigned char)SOCKS_ATYPE_IPV6 ?              \
            sizeof((packet)->host.addr.ipv6.ip)                                \
          : (strlen((packet)->host.addr.domain) + 1))

void _udp_data_transform_cb( socks_worker_process_t *process, int fd, int events,  void *arg);


#endif //SOCKD_UDP_H_
