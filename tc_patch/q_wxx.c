/*
 * q_wxx.c		wxx Scheduler.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Qixuan Wang <qixuan.wang@hotmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"
#include "linux/wxx.h"

static void explain(void)
{
    fprintf(stderr, "Usage: ... wxx [ limit PACKETS ] [ flows NUMBER ]\n");
    fprintf(stderr, "                  [ [no]ecn ]\n");
}

static int wxx_parse_opt(struct qdisc_util *qu, int argc, char **argv, struct nlmsghdr *n)
{
    unsigned limit = 0;
    unsigned flows = 0;
    unsigned ecn = -1;

    struct rtattr *tail;

	while (argc > 0) {
        if (strcmp(*argv, "limit") == 0) {
            NEXT_ARG();
            if (get_unsigned(&limit, *argv, 0)) {
                fprintf(stderr, "Illegal \"limit\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "flows") == 0) {
            NEXT_ARG();
            if (get_unsigned(&flows, *argv, 0)) {
                fprintf(stderr, "Illegal \"flows\"\n");
                return -1;
            }
        } else if (strcmp(*argv, "ecn") == 0) {
            ecn = 1;
        } else if (strcmp(*argv, "noecn") ==0) {
            ecn = 0;
        } else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
        argc--; argv++;
	}

    tail = NLMSG_TAIL(n);
    addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);

    if(limit) {
        addattr_l(n, 1024, TCA_WXX_LIMIT, &limit, sizeof(limit));
    }
    if(flows) {
        addattr_l(n, 1024, TCA_WXX_FLOWS, &flows, sizeof(flows));
    }
    if(ecn != -1) {
        addattr_l(n, 1024, TCA_WXX_ECN, &ecn, sizeof(ecn));
    }

    tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;

	return 0;
}

static int wxx_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
    unsigned int limit;
    unsigned int flows;
    int ecn;

    struct rtattr *tb[TCA_WXX_MAX + 1];

	if (opt == NULL)
		return 0;

    parse_rtattr_nested(tb, TCA_WXX_MAX, opt);

    if(tb[TCA_WXX_LIMIT] && RTA_PAYLOAD(tb[TCA_WXX_LIMIT]) >= sizeof(__u32)) {
        limit = rta_getattr_u32(tb[TCA_WXX_LIMIT]);
        fprintf(f, "limit %up ", limit);
    }

    if(tb[TCA_WXX_FLOWS] && RTA_PAYLOAD(tb[TCA_WXX_FLOWS]) >= sizeof(__u32)) {
        flows = rta_getattr_u32(tb[TCA_WXX_FLOWS]);
        fprintf(f, "flows %u ", flows);
    }

    if(tb[TCA_WXX_ECN] && RTA_PAYLOAD(tb[TCA_WXX_ECN]) >= sizeof(__u8)) {
         ecn = rta_getattr_u8(tb[TCA_WXX_ECN]);
         if(ecn == 0) {
             fprintf(f, "noecn");
         } else {
             fprintf(f, "ecn");
         }
    }


	return 0;
}

static int wxx_print_xstats(struct qdisc_util *qu, FILE *f, struct rtattr *xstats)
{
    struct tc_wxx_stats *st;

	if (xstats == NULL)
		return 0;

    if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;
	st = RTA_DATA(xstats);

    fprintf(f, " qlen %u, active flows %llu, idle flows %llu, overlimit %llu ",
            st->qlen, st->active_flows, st->idle_flows, st->overlimit);
	return 0;
}

struct qdisc_util wxx_qdisc_util = {
	.id		= "wxx",
    .parse_qopt	= wxx_parse_opt,
    .print_qopt	= wxx_print_opt,
    .print_xstats	= wxx_print_xstats
};
