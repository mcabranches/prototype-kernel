/*
 * Basic unit test module for linux/skb_array.h
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skb_array.h>

//#include <linux/skbuff.h>
struct sk_buff;

static int verbose=1;

static bool basic_init_and_cleanup(void)
{
	struct skb_array queue;
	int result;

	result = skb_array_init(&queue, 42, GFP_KERNEL);
	if (result < 0)
		return false;
	/* MST argued size should not be rounded up */
	if (queue.size != 42)
		return false;

	skb_array_cleanup(&queue);
	return true;
}

static bool basic_add_and_remove_object(void)
{
	struct skb_array queue;
	struct sk_buff *skb, *nskb;
	int result, r;

	/* Fake pointer value to enqueue */
	skb = (struct sk_buff *)(unsigned long)42;

	result = skb_array_init(&queue, 123, GFP_KERNEL);
	if (result < 0)
		return false;

	r = skb_array_produce_bh(&queue, skb);	/* enqueue */
	if (r < 0) {
		result = false; /* enq failed */
		goto out;
	}
	nskb = skb_array_consume_bh(&queue);	/* dequeue */
	if (skb != nskb)			/* validate object */
		result = false;
	else
		result = true;
out:
	skb_array_cleanup(&queue);
	return result;
}

static bool test_queue_full_condition(void)
{
	struct skb_array queue;
	struct sk_buff *skb;
	int result, r;
	int i;
#define Q_SIZE 33

	/* Fake pointer value to enqueue */
	skb = (struct sk_buff *)(unsigned long)42;

	result = skb_array_init(&queue, Q_SIZE, GFP_KERNEL);
	if (result < 0)
		return false;

	/* Try to enq more elements than queue size */
	for (i = 0; i < (Q_SIZE * 2); i++) {
		r = skb_array_produce_bh(&queue, skb);	/* enqueue */
		if (r < 0) /* -ENOSPC = queue condition full is reached */
			break;
	}

	if (i == Q_SIZE)
		result = true;
	else
		result = false;

	skb_array_cleanup(&queue);
	return result;
#undef Q_SIZE
}

static bool test_queue_empty_condition(void)
{
	struct skb_array queue;
	struct sk_buff *skb, *nskb;
	int result, r;
#define Q_SIZE 4

	/* Fake pointer value to enqueue */
	skb = (struct sk_buff *)(unsigned long)42;

	result = skb_array_init(&queue, Q_SIZE, GFP_KERNEL);
	if (result < 0)
		return false;

	/* Try to dequeue from empty queue, must fail */
	nskb = skb_array_consume_bh(&queue);
	if (nskb == NULL) /* deq must fail */
		result = true;
	else {
		result = false;
		goto out; /* failed */
	}

	/* Test: enq 1 obj, deq 2 objects */
	r = skb_array_produce_bh(&queue, skb);	/* enqueue */
	if (r < 0) {
		result = false; /* enq failed */
		goto out;
	}
	nskb = skb_array_consume_bh(&queue);
	nskb = skb_array_consume_bh(&queue);
	if (nskb == NULL) /* deq 2nd obj must fail */
		result = true;
	else
		result = false;
out:
	skb_array_cleanup(&queue);
	return result;
#undef Q_SIZE
}

#define TEST_FUNC(func) 					\
do {								\
	if (!(func)) {						\
		pr_info("FAILED - " #func "\n");		\
		return -1;					\
	} else {						\
		if (verbose)					\
			pr_info("PASSED - " #func "\n");	\
		passed_count++;					\
	}							\
} while (0)

int run_basic_tests(void)
{
	int passed_count = 0;
	TEST_FUNC(basic_init_and_cleanup());
	TEST_FUNC(basic_add_and_remove_object());
	TEST_FUNC(test_queue_full_condition());
	TEST_FUNC(test_queue_empty_condition());

	return passed_count;
}

static int __init skb_array_test01_module_init(void)
{
	if (verbose)
		pr_info("Loaded\n");

	if (run_basic_tests() < 0)
		return -ECANCELED;

	return 0;
}
module_init(skb_array_test01_module_init);

static void __exit skb_array_test01_module_exit(void)
{
	if (verbose)
		pr_info("Unloaded\n");
}
module_exit(skb_array_test01_module_exit);

MODULE_DESCRIPTION("SKB array basic unit test of API");
MODULE_AUTHOR("Jesper Dangaard Brouer <netoptimizer@brouer.com>");
MODULE_LICENSE("GPL");