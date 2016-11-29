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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <libubox/blobmsg_json.h>
#include "libubus.h"

static struct ubus_context *ctx;
static struct blob_buf buf;


enum {
    CONFIG_APNAME,
    CONFIG_STANAME,
    CONFIG_SSID,
    CONFIG_PASSWD,
    CONFIG_CHANNEL,
    CONFIG_SECURITY,
    CONFIG_BSSID,
    __CONFIG_MAX
};

static const struct blobmsg_policy connect_policy[__CONFIG_MAX] = {
    [CONFIG_APNAME] = { .name = "apname", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_STANAME] = { .name = "staname", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_PASSWD] = { .name = "passwd", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_SECURITY] = { .name = "security", .type = BLOBMSG_TYPE_STRING },
    [CONFIG_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
};

static char isStaGetIP(const char* staname)
{

    int socket_fd;
    struct sockaddr_in *sin;
    struct ifreq ifr;
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1)
    {
        return 0;
    }
    strcpy(ifr.ifr_name, staname);

    if (ioctl(socket_fd, SIOCGIFADDR, &ifr) < 0)
    {
        return 0;
    } else
    {
        sin = (struct sockaddr_in *)&(ifr.ifr_addr);
        syslog(LOG_INFO,"current IP = %s\n", inet_ntoa(sin->sin_addr));
        return 1;
    }

}

static int apClient_connect(struct ubus_context *ctx, struct ubus_object *obj,
                           struct ubus_request_data *req, const char *method,
                           struct blob_attr *msg)
{
    struct blob_attr *tb[__CONFIG_MAX];
    int try_count = 0; 
    int wait_count = 3;
    const char *apname;
    const char *staname;
    const char *ssid;
    const char *passwd;
    const char *channel;
    const char *security;
    const char *bssid;
    char *crypto;

    char cmd[100];
    blobmsg_parse(connect_policy, __CONFIG_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[CONFIG_APNAME]) return UBUS_STATUS_INVALID_ARGUMENT;

    blob_buf_init(&buf, 0);
    apname = blobmsg_data(tb[CONFIG_APNAME]);
    staname = blobmsg_data(tb[CONFIG_STANAME]);
    ssid = blobmsg_data(tb[CONFIG_SSID]);
    passwd = blobmsg_data(tb[CONFIG_PASSWD]);

    channel = blobmsg_data(tb[CONFIG_CHANNEL]);
    security = blobmsg_data(tb[CONFIG_SECURITY]); 

    crypto = strstr(security, "/");
    if (crypto) {
        *crypto = '\0';
        crypto++;
    }
    wifi_site_survey(apname,NULL,0);

    wifi_repeater_start(apname, staname, channel, ssid, passwd, security, crypto);

    /*ifconfig staname down*/
    snprintf(cmd, lengthof(cmd) - 1, "ifconfig  %s down", staname);
    system(cmd);

    /*ifconfig staname down*/
    snprintf(cmd, lengthof(cmd) - 1, "ifconfig  %s  up", staname);
    system(cmd);


    /*use uci set ssid*/
    snprintf(cmd, lengthof(cmd) - 1, "uci set wireless.sta.ApCliSsid=%s", ssid);
    system(cmd);

     /*use uci set key*/
    snprintf(cmd, lengthof(cmd) - 1, "uci set wireless.sta.ApCliWPAPSK=%s", passwd);
    system(cmd);

     /*uci commit*/
    snprintf(cmd, lengthof(cmd) - 1, "uci commit");
    system(cmd);


     /*udhcpc -i apcli0*/
    snprintf(cmd, lengthof(cmd) - 1, "udhcpc -n -q -i apcli0");
    system(cmd);

    while (wait_count--) {
        if (isStaGetIP(staname)) {
             blobmsg_add_string(&buf, "result", "success");
             break;
        }
        sleep(1);
    }
    if (wait_count == -1) {
        blobmsg_add_string(&buf, "result", "failed");
    }

    ubus_send_reply(ctx, req, buf.head);
    return UBUS_STATUS_OK;
}




static const struct ubus_method apClient_methods[] = {
   // UBUS_METHOD("scan", apClient_scan, scan_policy),
    UBUS_METHOD("connect", apClient_connect, connect_policy),
};

static struct ubus_object_type apClient_object_type =
UBUS_OBJECT_TYPE("rewifi", apClient_methods);

static struct ubus_object apClient_object = {
    .name = "rewifi",
    .type = &apClient_object_type,
    .methods = apClient_methods,
    .n_methods = ARRAY_SIZE(apClient_methods),
};

static void server_main(void)
{
    int ret;

    ret = ubus_add_object(ctx, &apClient_object);
    if (ret) fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));

    uloop_run();
}


int main(int argc, char **argv)
{

    while (isStaGetIP("apcli0") == 0) {
        sleep(1);
    }
    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    openlog("checkupgrade", 0, 0);

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
