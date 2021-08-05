// +build ignore

#include "../include/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define IPV6_FLOWLABEL_MASK __bpf_constant_htonl(0x000FFFFF)
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)

SEC("license") char _license[] = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} pipe SEC(".maps");

enum {
	AF_INET  = 2,
	AF_INET6 = 10,
};

struct flow_t {
	__u32 syn_flow_lbl, ack_flow_lbl;
	struct in6_addr laddr, raddr;
	__le16 lport;
	__be16 rport;
};

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kprobe__tcp_set_state, struct sock *sk, int state)
{
	if (state != BPF_TCP_ESTABLISHED)
		return 0;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET6)
		return 0;

	struct saved_syn *saved_syn = BPF_CORE_READ((struct tcp_sock *)sk, saved_syn);
	if (!saved_syn)
		return 0;

	// First 32 bit word of saved_syn is the length of the buffer.
	__u32 syn_flow_lbl;
	if (bpf_probe_read(&syn_flow_lbl, sizeof(syn_flow_lbl), saved_syn + 1))
		return 0;

	syn_flow_lbl &= IPV6_FLOWLABEL_MASK;

	__u32 ack_flow_lbl = BPF_CORE_READ((struct tcp6_sock *)sk, inet6.rcv_flowinfo) & IPV6_FLOWLABEL_MASK;
	if (syn_flow_lbl == ack_flow_lbl)
		return 0;

	struct flow_t flow = {
		.syn_flow_lbl = syn_flow_lbl,
		.ack_flow_lbl = ack_flow_lbl,
		.laddr        = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr),
		.raddr        = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr),
		.lport        = BPF_CORE_READ(sk, __sk_common.skc_num),
		.rport        = BPF_CORE_READ(sk, __sk_common.skc_dport),
	};

	bpf_perf_event_output(ctx, &pipe, BPF_F_CURRENT_CPU, &flow, sizeof(flow));

	return 0;
}
