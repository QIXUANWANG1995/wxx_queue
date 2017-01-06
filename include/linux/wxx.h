#ifndef __LINUX_WXX_H
#define __LINUX_WXX_H

#include <linux/types.h>

/* Wxx Scheduler */
enum {
    TCA_WXX_UNSPEC,
    TCA_WXX_FLOWS,
    TCA_WXX_ECN,
    TCA_WXX_LIMIT,
    __TCA_WXX_MAX
};

struct tc_wxx_stats {
    unsigned int qlen;
    __u64 active_flows;
    __u64 idle_flows;
    __u64 overlimit;
};

#define TCA_WXX_MAX (__TCA_WXX_MAX - 1)
#endif
