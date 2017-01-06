#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#include <net/flow_keys.h>
#endif

#include "linux/wxx.h"

/* wxx Queue Scheduler
 *
 * The wxx queue scheduler is flow based and the packets are classified using
 * the hash methed.
 *
 * The wxx queue scheduler follow the simple principle:
 *
 * 1. Small flows are latency sensitive and large flows require large throughput.
 * 2. Schedule the small flows first.
 * 3. The queue of a smaller queue should be kept smaller and vice versa.
 *
 * The operation of the wxx queue is described as follows:
 *
 * enqueue():
 *  1. Classify the packet to the flow. Search the flow queue through the flow
 *  list.
 *  2. If the queue exists, select the queue and mark it active if needed.
 *  Compares the bytes sent of the queue with the next queue on the queue list,
 *  if it has sent more bytes than the next queue, swap the two queues.
 *  3. Otherwise, create the queue for the flow and put the queue at the head of
 *  the queue list.
 *  4. Update bytes set informatin
 *  5. Enqueue the packet.
 *
 * dequeue():
 *  1. Select the header queue of the queue list.
 *  2. Dequeue the packet.
 *  3. Mark ECN according to the flow queue length.
 *  3. If there is no packet in the queue, mark it inactive.
 *
 * If the queue has been inactive for a period, the bytes sent should be cleared.
 */

#define FLOW_TIME_OUT 1000      /* 1 second */

enum flow_status {
    ACTIVE,
    IDLE,
    NOT_IN_LIST
};

struct wxx_flow_queue {
    struct sk_buff *head;       /* The flow queue implementation */
    struct sk_buff *tail;

    unsigned int length;        /* Actual flow length */
    u32 bytes_length;           /* Already set bytes (different among queues) */

    enum flow_status status;
    unsigned int last_active_time;      /* The last active time */

    struct list_head flow_chain;
};

struct wxx_sched_data {
    struct wxx_flow_queue    /* Flow table, wxx_flow_queue[FLOW_TOTAL]*/
        *flow_table;            /* The table is used in enqueue since it's fast to look up the flow */

    u32 total_flow;             /* The total flow */

    u8 ecn;                     /* 1 for enable ECN, 0 for non ECN */

    u32 perturbation;           /* The hash perturbation */

    u32 total_bytes_length;

    u64 stat_overlimit;
    u64 stat_active_flows;
    u64 stat_idle_flows;

    struct list_head active_flow_list; /* The linked list is used in the dequeue since it is used to keep the order */
    struct wxx_flow_queue *fattest_flow; /* We should drop packets from the fattest_flow */
};

/* Reference: fq_codel */
/* If kernel version >= 4.2, we don't use the flow dissect operation but
 * use skb_get_hash_perturb function instead */
static unsigned int
wxx_classify(struct sk_buff *skb, u32 perturbation, u32 total_flow)
{
    u32 hash;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    struct flow_keys keys;
    skb_flow_dissect(skb, &keys);
    hash = jhash_3words((__force u32)keys.dst,
                        (__force u32)keys.src ^ keys.ip_proto,
                        (__force u32)keys.ports, perturbation);
#else
    hash = skb_get_hash_perturb(skb, perturbation);
#endif

    return reciprocal_scale(hash, total_flow);
}

static inline struct sk_buff*
wxx_flow_dequeue(struct wxx_flow_queue *flow)
{
    struct sk_buff *skb;

    skb = flow->head;
    if(skb == NULL) {
        return NULL;
    }
    flow->head = skb->next;
    skb->next = NULL;

    return skb;
}

static inline void
wxx_flow_enqueue(struct sk_buff *skb, struct wxx_flow_queue *flow)
{
    if (flow->head == NULL) {
        flow->head = skb;
    } else {
        flow->tail->next = skb;
    }
    flow->tail = skb;
    skb->next = NULL;
}

static unsigned int
wxx_drop(struct Qdisc *sch)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    unsigned int prev_backlog = sch->qstats.backlog;
    struct sk_buff *skb;

    printk(KERN_INFO "Dropping packet ...\n");

    /* Drop from the fattest flow */
    skb = wxx_flow_dequeue(q->fattest_flow);

    sch->q.qlen--;
    q->fattest_flow->length--;
    qdisc_qstats_drop(sch);
    qdisc_qstats_backlog_dec(sch, skb);
    kfree(skb);
    return prev_backlog - sch->qstats.backlog;
}

static int
wxx_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    unsigned int now = jiffies_to_msecs(jiffies);
    unsigned int idx;
    struct wxx_flow_queue *flow;
    struct wxx_flow_queue *next_flow;

    /* Classify the flows */
    idx = wxx_classify(skb, q->perturbation, q->total_flow);
    flow = q->flow_table + idx;

    /* Enqueue the packet */
    wxx_flow_enqueue(skb, flow);

    /* Update the backlog */
    qdisc_qstats_backlog_inc(sch, skb);

    /* Update the flow information */
    if (flow->status == NOT_IN_LIST) {
        list_add(&flow->flow_chain, &q->active_flow_list);
        q->stat_active_flows++;
    } else if (flow->status == IDLE) {
        /* TODO check whether we need to move it to the head */
        list_move(&flow->flow_chain, &q->active_flow_list);
        q->stat_active_flows++;
        q->stat_idle_flows--;
    } else {
        /* The flow queue is active, compare it with the next flow of the active flow list, and
         * determine whether the flow order should be adjusted */
        next_flow = list_next_entry(flow, flow_chain);
        if(next_flow && flow->bytes_length + qdisc_pkt_len(skb) >= next_flow->bytes_length) {
            /* The follow has gradually become fatter, move it lower */
            list_move(&flow->flow_chain, &next_flow->flow_chain);
        }
    }
    flow->status = ACTIVE;
    flow->bytes_length += qdisc_pkt_len(skb);
    flow->last_active_time = now;
    flow->length++;

    q->total_bytes_length += qdisc_pkt_len(skb);

    /* Update the fattest flow if necessary */
    if(unlikely(list_is_last(&flow->flow_chain, &q->active_flow_list))) {
        q->fattest_flow = flow;
    }

    /* Check if the queue has over limit */
    if (++sch->q.qlen <= sch->limit) {
         return NET_XMIT_SUCCESS;
    }

    q->stat_overlimit++;

    /* Drop packet */
    /* TODO When the queue is full, do we need to drop more packets */
    wxx_drop(sch);

    qdisc_tree_decrease_qlen(sch, 1);

    if (flow == q->fattest_flow) {
        return NET_XMIT_CN;
    }

    return NET_XMIT_SUCCESS;
}

static struct sk_buff*
wxx_dequeue(struct Qdisc *sch)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    struct wxx_flow_queue *flow;
    struct sk_buff *skb;
    unsigned int now = jiffies_to_msecs(jiffies);

begin:
    if (list_empty(&q->active_flow_list)) {
        return NULL;
    }

    flow = list_first_entry(&q->active_flow_list, struct wxx_flow_queue, flow_chain);

    if (flow->status == ACTIVE) {
        skb = wxx_flow_dequeue(flow);
        if(!skb) {
            flow->status = IDLE;
            list_move_tail(&flow->flow_chain, &q->active_flow_list);
            q->stat_active_flows--;
            q->stat_idle_flows++;
            goto begin;
        }
    } else {
        /* Check whether the tail flow queue can be removed */

        struct wxx_flow_queue *tmp;

        list_for_each_entry_safe(flow, tmp, &q->active_flow_list, flow_chain) {
            if (flow->status == ACTIVE) {
            /* Bug occurs if the tail flow is active but the head is not */
                printk(KERN_INFO "Finding active flow in the tail, which is expected not to happen ...\n");
                list_move(&flow->flow_chain, &q->active_flow_list);
                goto begin;
            }

            if (flow->status == IDLE && now - flow->last_active_time > FLOW_TIME_OUT) {
                /* The flow has been idle for a long time, remove it ... */
                list_del_init(&flow->flow_chain);
                flow->status = NOT_IN_LIST;
                flow->bytes_length = 0;
                flow->last_active_time = 0;
                q->stat_idle_flows--;
            }
        }

        return NULL;
    }

    /* TODO ECN Marking */

    flow->length--;
    sch->q.qlen--;

    qdisc_qstats_backlog_dec(sch, skb);
    qdisc_bstats_update(sch, skb);
    qdisc_tree_decrease_qlen(sch, 1);

    return skb;
}

static struct sk_buff*
wxx_peek(struct Qdisc *sch)
{
    return NULL;
}

static const struct nla_policy wxx_policy[TCA_WXX_MAX + 1] = {
    [TCA_WXX_FLOWS] = {.type = NLA_U32},
    [TCA_WXX_LIMIT] = {.type = NLA_U32},
    [TCA_WXX_ECN] = {.type = NLA_U8},
};

static void
wxx_rehash(struct wxx_flow_queue *old_table, u32 old_total_flow,
        struct wxx_flow_queue *new_table, u32 new_total_flow, u32 perturbation)
{
    struct wxx_flow_queue *flow;
    struct sk_buff *skb;
    int idx;
    int i;

    printk(KERN_INFO "Rehashing wxx queue ...\n");

    for (i = 0; i < old_total_flow; i++) {
        flow = old_table + i;
        if (flow->head == NULL) {
            continue;
        }
        skb = flow->head;
        idx = wxx_classify(skb, perturbation, new_total_flow);
        memcpy(new_table + idx, flow, sizeof(struct wxx_flow_queue));
    }
}

static int
wxx_resize(struct wxx_sched_data *q, u32 new_total_flow)
{
    struct wxx_flow_queue *new_flow_table;
    int i;

    printk(KERN_INFO "Resizing wxx queue ...\n");

    if(q->total_flow == new_total_flow) {
        return 0;
    }

    new_flow_table = kcalloc(new_total_flow,
            sizeof(struct wxx_flow_queue), GFP_KERNEL);

    if(!new_flow_table) {
        return -ENOMEM;
    }

    for (i = 0; i < new_total_flow; i++) {
        struct wxx_flow_queue *flow =
            (struct wxx_flow_queue*)(new_flow_table + i);
        flow->status = NOT_IN_LIST;
        INIT_LIST_HEAD(&flow->flow_chain);
    }

    if(q->flow_table) {
        wxx_rehash(q->flow_table, q->total_flow, new_flow_table,
                new_total_flow, q->perturbation);

        kvfree(q->flow_table);
    }

    q->flow_table = new_flow_table;
    q->total_flow = new_total_flow;

    return 0;
}

static int
wxx_change(struct Qdisc *sch, struct nlattr *opt)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    struct nlattr *tb[TCA_WXX_MAX + 1];

    int err, drop_count = 0;

    printk(KERN_INFO "Changing wxx queue ...\n");

    if(!opt) {
         return -EINVAL;
    }

    err = nla_parse_nested(tb, TCA_WXX_MAX, opt, wxx_policy);

    if (err < 0) {
        return err;
    }

    sch_tree_lock(sch);

    if(tb[TCA_WXX_FLOWS]) {
        u32 total_flow = nla_get_u32(tb[TCA_WXX_FLOWS]);
        wxx_resize(q, total_flow);
    }

    if(tb[TCA_WXX_LIMIT]) {
        sch->limit = nla_get_u32(tb[TCA_WXX_LIMIT]);
    }

    if(tb[TCA_WXX_ECN]) {
        q->ecn = nla_get_u8(tb[TCA_WXX_ECN]);
    }

    while(sch->q.qlen > sch->limit) {
        wxx_drop(sch);
        drop_count++;
    }

    qdisc_tree_decrease_qlen(sch, drop_count);

    sch_tree_unlock(sch);

    return err;
}

static int
wxx_init(struct Qdisc *sch, struct nlattr *opt)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    int err;

    printk(KERN_INFO "Initing wxx queue...\n");

    sch->limit = 1000;
    q->ecn = 1;
    q->perturbation = prandom_u32();

    q->stat_overlimit = 0;
    q->stat_active_flows = 0;

    INIT_LIST_HEAD(&q->active_flow_list);

    err = wxx_resize(q, 1024);

    if (err < 0) {
        return err;
    }

    if (opt) {
        err = wxx_change(sch, opt);
    }

    return err;
}

static void
wxx_reset(struct Qdisc *sch)
{
     struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    int i;

    printk(KERN_INFO "Resetting wxx queue ...\n");

    for (i = 0; i < q->total_flow; i++) {
         struct wxx_flow_queue *flow = q->flow_table + i;
         while(flow->head) {
             struct sk_buff *skb = wxx_flow_dequeue(flow);

             qdisc_qstats_backlog_dec(sch, skb);
             kfree_skb(skb);
         }
         INIT_LIST_HEAD(&flow->flow_chain);
         flow->length = 0;
         flow->bytes_length = 0;
         flow->status = NOT_IN_LIST;
         flow->last_active_time = 0;
    }
    INIT_LIST_HEAD(&q->active_flow_list);
    q->total_bytes_length = 0;
    q->fattest_flow = NULL;
    q->stat_overlimit = 0;
    q->stat_active_flows = 0;
    q->stat_idle_flows = 0;
}

static void
wxx_destroy(struct Qdisc *sch)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);

    printk(KERN_INFO "Destroying wxx queue ...\n");
    wxx_reset(sch);
    kvfree(q->flow_table);
}

static int
wxx_dump(struct Qdisc *sch, struct sk_buff *skb)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    struct nlattr *opts;

    opts = nla_nest_start(skb, TCA_OPTIONS);
    if(opts == NULL) {
        goto err;
    }

    if(nla_put_u32(skb, TCA_WXX_LIMIT, sch->limit) ||
            nla_put_u32(skb, TCA_WXX_FLOWS, q->total_flow) ||
            nla_put_u8(skb, TCA_WXX_ECN, q->ecn)) {
        goto err;
    }

    return nla_nest_end(skb, opts);

err:
    return -1;
}

static int
wxx_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
    struct wxx_sched_data *q = (struct wxx_sched_data*) qdisc_priv(sch);
    struct tc_wxx_stats st = {
        .qlen = sch->q.qlen,
        .active_flows = q->stat_active_flows,
        .idle_flows = q->stat_idle_flows,
        .overlimit = q->stat_overlimit
    };

    return gnet_stats_copy_app(d, &st, sizeof(st));
}

struct Qdisc_ops wxx_qdisc_ops __read_mostly = {
    .id = "wxx",
    .priv_size = sizeof(struct wxx_sched_data),
    .enqueue = wxx_enqueue,
    .dequeue = wxx_dequeue,
    .peek = wxx_peek,
    .drop = wxx_drop,
    .init = wxx_init,
    .reset = wxx_reset,
    .destroy = wxx_destroy,
    .change = wxx_change,
    .dump = wxx_dump,
    .dump_stats = wxx_dump_stats,
    .owner = THIS_MODULE
};

static int
__init wxx_module_init(void)
{
    printk(KERN_INFO "wxx module init...\n");
    return register_qdisc(&wxx_qdisc_ops);
}

static void
__exit wxx_module_exit(void)
{
    unregister_qdisc(&wxx_qdisc_ops);
    printk(KERN_INFO "wxx module exit...\n");
}

module_init(wxx_module_init);
module_exit(wxx_module_exit);

MODULE_DESCRIPTION("wxx scheduler");
MODULE_AUTHOR("Qixuan Wang");
MODULE_LICENSE("GPL");
