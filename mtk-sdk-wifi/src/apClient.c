/*
 * 2016 Copyright (c) Seeed Technology Inc.  All right reserved.
 * Author:Baozhu Zuo <zuobaozhu@gmail.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

#include <signal.h>

#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/un.h>
#include <poll.h>
#include <assert.h>
#include <linux/if.h>
#include <linux/types.h>
#include <linux/wireless.h>
#include <syslog.h>

#include <libubox/blobmsg_json.h>
#include "libubus.h"

static struct ubus_context *ctx;
static struct ubus_subscriber apClient_event;
static struct blob_buf b;

enum {
	SCAN_DEVICE,
	__SCAN_MAX
};

static const struct blobmsg_policy scan_policy[] = {
	[SCAN_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
};

struct scan_request {
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	int fd;
	int idx;
	char data[];
};

static void apClient_scan_fd_reply(struct uloop_timeout *t)
{
	struct scan_request *req = container_of(t, struct scan_request, timeout);
	char *data;

	data = alloca(strlen(req->data) + 32);
	sprintf(data, "msg%d: %s\n", ++req->idx, req->data);
	if (write(req->fd, data, strlen(data)) < 0) {
		close(req->fd);
		free(req);
		return;
	}

	uloop_timeout_set(&req->timeout, 1000);
}

static void apClient_scan_reply(struct uloop_timeout *t)
{
	struct scan_request *req = container_of(t, struct scan_request, timeout);
	int fds[2];

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "message", req->data);
	ubus_send_reply(ctx, &req->req, b.head);

	if (pipe(fds) == -1) {
		fprintf(stderr, "Failed to create pipe\n");
		return;
	}
	ubus_request_set_fd(ctx, &req->req, fds[0]);
	ubus_complete_deferred_request(ctx, &req->req, 0);
	req->fd = fds[1];

	req->timeout.cb = apClient_scan_fd_reply;
	apClient_scan_fd_reply(t);
}

static int apClient_scan(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct scan_request *hreq;
	struct blob_attr *tb[__SCAN_MAX];
	const char *format = "%s received a message: %s";
	const char *msgstr = "(unknown)";

	blobmsg_parse(scan_policy, ARRAY_SIZE(scan_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[SCAN_MSG])
		msgstr = blobmsg_data(tb[SCAN_MSG]);

	hreq = calloc(1, sizeof(*hreq) + strlen(format) + strlen(obj->name) + strlen(msgstr) + 1);
	if (!hreq)
		return UBUS_STATUS_UNKNOWN_ERROR;

	sprintf(hreq->data, format, obj->name, msgstr);
	ubus_defer_request(ctx, req, &hreq->req);
	hreq->timeout.cb = apClient_scan_reply;
	uloop_timeout_set(&hreq->timeout, 1000);

	return 0;
}

enum {
	CONFIG_IFNAME,
	CONFIG_STANAME,
    CONFIG_ESSID,
    CONFIG_PASSWD,
	__CONFIG_MAX
};

static const struct blobmsg_policy config_policy[__CONFIG_MAX] = {
	[CONFIG_IFNAME] = { .name = "IFNAME", .type = BLOBMSG_TYPE_STRING },
	[CONFIG_STANAME] = { .name = "STANAME", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_ESSID] = { .name = "ESSID", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_PASSWD] = { .name = "PASSWD", .type = BLOBMSG_TYPE_STRING },
};

static void
apClient_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s,
                   uint32_t id)
{
	fprintf(stderr, "Object %08x went away\n", id);
}

static int
apClient_notify(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
#if 0
	char *str;

	str = blobmsg_format_json(msg, true);
	fprintf(stderr, "Received notification '%s': %s\n", method, str);
	free(str);
#endif

	return 0;
}

static int apClient_config(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__CONFIG_MAX];
	int ret;

	blobmsg_parse(config_policy, __CONFIG_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[CONFIG_IFNAME])
		return UBUS_STATUS_INVALID_ARGUMENT;

	apClient_event.remove_cb = apClient_handle_remove;
	apClient_event.cb = apClient_notify;
	ret = ubus_subscribe(ctx, &apClient_event, blobmsg_get_u32(tb[CONFIG_IFNAME]));
	fprintf(stderr, "Watching object %08x: %s\n", blobmsg_get_u32(tb[CONFIG_IFNAME]), ubus_strerror(ret));
	return ret;
}




static const struct ubus_method apClient_methods[] = {
	UBUS_METHOD("scan", apClient_scan, scan_policy),
	UBUS_METHOD("config", apClient_config, config_policy),
};

static struct ubus_object_type apClient_object_type =
	UBUS_OBJECT_TYPE("apclient", apClient_methods);

static struct ubus_object apClient_object = {
	.name = "apclient",
	.type = &apClient_object_type,
	.methods = apClient_methods,
	.n_methods = ARRAY_SIZE(apClient_methods),
};

static void server_main(void)
{
	int ret;

	ret = ubus_add_object(ctx, &apClient_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));

	ret = ubus_register_subscriber(ctx, &apClient_event);
	if (ret)
		fprintf(stderr, "Failed to add config handler: %s\n", ubus_strerror(ret));

	uloop_run();
}

int main(int argc, char **argv)
{
	const char *ubus_socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "cs:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		default:
			break;
		}
	}

	argc -= optind;
	argv += optind;

	uloop_init();
	signal(SIGPIPE, SIG_IGN);

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ctx);

	server_main();

	ubus_free(ctx);
	uloop_done();

	return 0;
}
