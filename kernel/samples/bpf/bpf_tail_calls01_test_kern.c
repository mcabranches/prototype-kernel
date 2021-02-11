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


struct bpf_map_def SEC("maps") jmp_table1 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 100,
};

//m: used to test tail calls on multiple "entry point tables"*/
/*struct bpf_map_def SEC("maps") jmp_table2 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 100,
};*/


//m: map to hold a counter
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 1,
};




static __always_inline __u32 update_counter(void)
{
    __u32 *count;
    __u32 key = 0;
    count = bpf_map_lookup_elem(&xdp_stats_map, &key);
    //bpf_debug("hi");
    if (count){
        *count += 1;
        //bpf_debug("XDP: count was here! %u\n", *count);

        return *count;
    }
    else{
        return 0;
    }
}

/* Main/root ebpf xdp program */
SEC("xdp1")
int  xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
    //__u32 count;
	

	/* Validate packet length is minimum Eth header size */
	if (eth + 1 > data_end)
		return XDP_ABORTED;
    
    /*m: (START) test alternating jump tables*/
    //count = update_counter();
    //bpf_debug("Counter %d\n", count);
    /*if (count % 3){
        bpf_debug("jmp_table1\n");
	    bpf_tail_call(ctx, &jmp_table1, 1);
    }
    else{
        bpf_debug("jmp_table2\n");
        bpf_tail_call(ctx, &jmp_table2, 1);
    }*/
    /*m: (END) test alternating jump tables*/

    bpf_tail_call(ctx, &jmp_table1, 1);
	/* bpf_tail_call on empty jmp_table entry, cause fall-through.
	 * (Normally a bpf_tail_call never returns)
	 */
	bpf_debug("XDP: jmp_table empty, reached fall-through action\n");
    
	return XDP_PASS;
}

/* Setup of jmp_table is (for now) done manually in _user.c.
 *
 * Notice: bpf_load.c have support for auto-populating for "socket/N",
 * "kprobe/N" and "kretprobe/N" (TODO: add support for "xdp/N").
 */

/* Tail call index=1 */
SEC("xdp_1")
int  xdp_tail_call_1(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_1 ) id=1 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 2);
    return XDP_PASS;
}

SEC("xdp_2")
int  xdp_tail_call_2(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_2 ) id=2 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 3);
    return XDP_PASS;
}

SEC("xdp_3")
int  xdp_tail_call_3(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_3 ) id=3 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 4);
    return XDP_PASS;
}

SEC("xdp_4")
int  xdp_tail_call_4(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_4 ) id=4 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 5);
    return XDP_PASS;
}

SEC("xdp_5")
int  xdp_tail_call_5(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_5 ) id=5 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 6);
    return XDP_PASS;
}

SEC("xdp_6")
int  xdp_tail_call_6(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_6 ) id=6 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 7);
    return XDP_PASS;
}

SEC("xdp_7")
int  xdp_tail_call_7(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_7 ) id=7 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 8);
    return XDP_PASS;
}

SEC("xdp_8")
int  xdp_tail_call_8(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_8 ) id=8 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 9);
    return XDP_PASS;
}

SEC("xdp_9")
int  xdp_tail_call_9(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_9 ) id=9 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 10);
    return XDP_PASS;
}

SEC("xdp_10")
int  xdp_tail_call_10(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_10 ) id=10 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 11);
    return XDP_PASS;
}

SEC("xdp_11")
int  xdp_tail_call_11(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_11 ) id=11 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 12);
    return XDP_PASS;
}

SEC("xdp_12")
int  xdp_tail_call_12(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_12 ) id=12 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 13);
    return XDP_PASS;
}

SEC("xdp_13")
int  xdp_tail_call_13(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_13 ) id=13 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 14);
    return XDP_PASS;
}

SEC("xdp_14")
int  xdp_tail_call_14(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_14 ) id=14 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 15);
    return XDP_PASS;
}

SEC("xdp_15")
int  xdp_tail_call_15(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_15 ) id=15 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 16);
    return XDP_PASS;
}

SEC("xdp_16")
int  xdp_tail_call_16(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_16 ) id=16 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 17);
    return XDP_PASS;
}

SEC("xdp_17")
int  xdp_tail_call_17(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_17 ) id=17 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 18);
    return XDP_PASS;
}

SEC("xdp_18")
int  xdp_tail_call_18(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_18 ) id=18 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 19);
    return XDP_PASS;
}

SEC("xdp_19")
int  xdp_tail_call_19(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_19 ) id=19 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 20);
    return XDP_PASS;
}

SEC("xdp_20")
int  xdp_tail_call_20(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_20 ) id=20 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 21);
    return XDP_PASS;
}

SEC("xdp_21")
int  xdp_tail_call_21(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_21 ) id=21 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 22);
    return XDP_PASS;
}

SEC("xdp_22")
int  xdp_tail_call_22(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_22 ) id=22 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 23);
    return XDP_PASS;
}

SEC("xdp_23")
int  xdp_tail_call_23(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_23 ) id=23 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 24);
    return XDP_PASS;
}

SEC("xdp_24")
int  xdp_tail_call_24(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_24 ) id=24 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 25);
    return XDP_PASS;
}

SEC("xdp_25")
int  xdp_tail_call_25(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_25 ) id=25 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 26);
    return XDP_PASS;
}

SEC("xdp_26")
int  xdp_tail_call_26(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_26 ) id=26 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 27);
    return XDP_PASS;
}

SEC("xdp_27")
int  xdp_tail_call_27(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_27 ) id=27 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 28);
    return XDP_PASS;
}

SEC("xdp_28")
int  xdp_tail_call_28(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_28 ) id=28 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 29);
    return XDP_PASS;
}

SEC("xdp_29")
int  xdp_tail_call_29(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_29 ) id=29 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 30);
    return XDP_PASS;
}

SEC("xdp_30")
int  xdp_tail_call_30(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_30 ) id=30 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 31);
    return XDP_PASS;
}

SEC("xdp_31")
int  xdp_tail_call_31(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_31 ) id=31 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 32);
    return XDP_PASS;
}

SEC("xdp_32")
int  xdp_tail_call_32(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_32 ) id=32 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 33);
    return XDP_PASS;
}

SEC("xdp_33")
int  xdp_tail_call_33(struct xdp_md *ctx)
{
    //bpf_debug("XDP: tail call (xdp_33 ) id=33 \n");
    update_counter();
    bpf_tail_call(ctx, &jmp_table1, 34);
    return XDP_PASS;
}


//m: I could not load more than XDP 76 sections
//Also the tail calls stop at "xdp_33"
//Actually it reaches the limit of 32 calls (see: https://docs.cilium.io/en/v1.9/bpf/)
//The number of loaded xdp sections do not appear to influence performance
//What impacts performance is the actual number of tail calls
