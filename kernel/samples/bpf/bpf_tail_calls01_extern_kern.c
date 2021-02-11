/*
 * Example of using bpf tail calls (in XDP programs)
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>

#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/*m: "extern" tail calls to be loaded dynamically 
on "bpf_tail_calls01_test_user.c"*/
SEC("xdp_1_2")
int  xdp_tail_call_1(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_1_2 )\n");
    return XDP_PASS;
}

SEC("xdp_2_2")
int  xdp_tail_call_2(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_2_2 )\n");
    return XDP_PASS;
}