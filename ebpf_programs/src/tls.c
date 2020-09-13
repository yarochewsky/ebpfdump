#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "parsing.h"
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/perf_event.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#define MAX_TLS 5

#define MAX_CPUS 4
#define AF_INET 2

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = MAX_CPUS,
};

struct proxy_entry {
  __u32 pid;
  __u32 addr;
};

struct bpf_map_def SEC("maps") proxy = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct proxy_entry),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") done = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u8),
  .max_entries = 1,
};

struct syscalls_enter_connect_args {
  __u64 __dont_touch;
  __u64 syscall_nr;
  __u64 fd;
  __u64 sockaddr;
  __u64 addrlen;
};

struct sockaddr {
   unsigned short   sa_family;
   char             sa_data[14];
};

struct content_type {
  __u8 __padding;
  __u8 id;
};

struct tls_header {
  char contents[5];
};

// struct tls_header {
//   char contents[5];
// };

// 0x16 0x01 03 e1 00 

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct syscalls_enter_connect_args* ctx) {
  __u32 pid, entry;
  struct proxy_entry* pe;
  
  entry = 0;
  pid = bpf_get_current_pid_tgid() >> 32;

  pe = bpf_map_lookup_elem(&proxy, &entry);
  if (!pe) {
    return 0;
  }

  struct sockaddr daddr;
  bpf_probe_read(&daddr, sizeof(struct sockaddr), (void*) ctx->sockaddr);

  if (daddr.sa_family != AF_INET) {
    return 0;
  }
  struct sockaddr_in* sin = (struct sockaddr_in*) &daddr;
  
  __u32 addr;
  bpf_probe_read(&addr, sizeof(__u32), &sin->sin_addr);
//  __u16 port = bpf_ntohs(sin->sin_port);
//  bpf_probe_read(&port, sizeof(port), &port);

  pe->pid = pid;
  pe->addr = bpf_ntohl(addr);

  bpf_printk("pid %d, addr %d\n", pid, pe->addr);

  __u32 cookie = 0xdeadbeef;
  return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &cookie, sizeof(cookie));
}


struct event {
  __u32 src_addr;
  __u32 dst_addr;

  __u16 src_port;
  __u16 dst_port;
};

SEC("xdp_tls")
int xdp_tls_prog(struct xdp_md* ctx) {
  int pkt_type;
  struct ethhdr* eth_hdr;
  struct ipv6hdr* ipv6_hdr;
  struct iphdr* ipv4_hdr;
  struct tcphdr* tcp_hdr;

  void* data_end = (void*) (long) ctx->data_end;
  void* data = (void*) (long) ctx->data;

  struct hdr_cursor hc = { .pos = data };

  pkt_type = parse_eth_vlan_header(&hc, data_end, &eth_hdr);
  if (pkt_type < 0) {
    return XDP_PASS;
  }

  if (pkt_type == bpf_htons(ETH_P_IP)) {
    pkt_type = parse_ipv4_header(&hc, data_end, &ipv4_hdr);
  } else if (pkt_type == bpf_htons(ETH_P_IPV6)) {
    pkt_type = parse_ipv6_header(&hc, data_end, &ipv6_hdr);
  } else {
    // unknown l2 protocol
    pkt_type = -1;
  }

  if (pkt_type < 0) {
    return XDP_PASS;
  }

  if (pkt_type != IPPROTO_TCP) {
    return XDP_PASS;
  }

  pkt_type = parse_tcp_header(&hc, data_end, &tcp_hdr);
  if (pkt_type < 0) {
    return XDP_PASS;
  }

  if (tcp_hdr->dest != bpf_ntohs(443)) {
    return XDP_PASS;
  }

  if (hc.pos + 1 > data_end) {
    return XDP_PASS;
  }

  char* tls_record = hc.pos;
  char p = tls_record[0];

  // if (hc.pos + sizeof(struct tls_header) > data_end) {
  //   return XDP_PASS;
  // }

  __u32 entry = 0;

struct tls_header* t;
char content_type;
unsigned short version, length;



#pragma unroll
for (int i = 0; i < MAX_TLS; i++) {

  // if (hc.pos == data_end) {
  //   return XDP_PASS;
  // }

  if (hc.pos + sizeof(struct tls_header) > data_end) {
      return XDP_PASS;
  }

    t = hc.pos;

    content_type = t->contents[0];
    version = bpf_ntohs((((unsigned short)t->contents[2])<<8) | t->contents[1]);
    length = bpf_ntohs((((unsigned short)t->contents[4])<<8) | t->contents[3]);


    bpf_printk("type %d, version %x, len: %x\n", content_type, version,
       length);

    hc.pos += sizeof(struct tls_header);

    if (length < 0 || length > 1000) {
      return XDP_PASS;
    }

    short l = length;

    if (l < 0 || l > 1000) {
      return XDP_PASS;
    }

    if (hc.pos + l > data_end) {
      bpf_printk("skipping on len %d\n", l);
      break;
    }

    hc.pos += l;

    if (content_type == 0x14) {
      bpf_printk("found %x", content_type);
      break;
    }
}

// bpf_printk("00: %x, 01: %x, 02: %x\n", t->contents[0],  t->contents[1],  t->contents[2]);


  if (content_type == 0x14) {

          bpf_printk("running code %x", content_type);

     __u32 src_addr = bpf_ntohl(ipv4_hdr->saddr);
     __u32 dst_addr = bpf_ntohl(ipv4_hdr->daddr);
     __u8* done_val = bpf_map_lookup_elem(&done, &entry);
     if (!done_val) return XDP_PASS;
      __u8 is_done = *done_val;
     if (is_done == 1) return XDP_PASS;

     __u16 src_port = tcp_hdr->source;
     __u16 dst_port = tcp_hdr->dest;
     tcp_hdr->dest = bpf_htons(8083);

    struct event e = {
      .src_addr = src_addr,
      .dst_addr = dst_addr,
      .src_port = src_port,
      .dst_port = dst_port,
    };

     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
//&src_addr, sizeof(src_addr));
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

