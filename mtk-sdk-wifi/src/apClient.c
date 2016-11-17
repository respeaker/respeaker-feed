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

struct survey_table {
    char channel[4];
    char ssid[32];
    char bssid[20];
    char security[23];
    char *crypto;
    char siganl[9];
};

static struct survey_table st[64];
static int survey_count = 0;

#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)
static void iwpriv(const char *name, const char *key, const char *val) {
    int socket_id;
    struct iwreq wrq;
    char data[64];

    snprintf(data, 64, "%s=%s", key, val);
    socket_id = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(wrq.ifr_ifrn.ifrn_name, name);
    wrq.u.data.length = strlen(data);
    wrq.u.data.pointer = data;
    wrq.u.data.flags = 0;
    ioctl(socket_id, RTPRIV_IOCTL_SET, &wrq);
    close(socket_id);
}

static void next_field(char **line, char *output, int n) {
    char *l = *line;
    int i;

    memcpy(output, *line, n);
    *line = &l[n];

    for (i = n - 1; i > 0; i--) {
        if (output[i] != ' ') break;
        output[i] = '\0';
    }
}

#define RTPRIV_IOCTL_GSITESURVEY (SIOCIWFIRSTPRIV + 0x0D)
static void wifi_site_survey(const char *ifname, const char *essid, int print) {
    char *s = malloc(IW_SCAN_MAX_DATA);
    int ret;
    int socket_id;
    struct iwreq wrq;
    char *line, *start;

    iwpriv(ifname, "SiteSurvey", (essid ? essid : ""));
    sleep(1);
    memset(s, 0x00, IW_SCAN_MAX_DATA);
    strcpy(wrq.ifr_name, ifname);
    wrq.u.data.length = IW_SCAN_MAX_DATA;
    wrq.u.data.pointer = s;
    wrq.u.data.flags = 0;
    socket_id = socket(AF_INET, SOCK_DGRAM, 0);
    ret = ioctl(socket_id, RTPRIV_IOCTL_GSITESURVEY, &wrq);
    close(socket_id);
    if (ret != 0) goto out;

    if (wrq.u.data.length < 1) goto out;

    /* ioctl result starts with a newline, for some reason */
    start = s;
    while (*start == '\n') start++;

    line = strtok((char *)start, "\n");
    line = strtok(NULL, "\n");
    survey_count = 0;
    while (line && (survey_count < 64)) {
        next_field(&line, st[survey_count].channel, sizeof(st->channel));
        next_field(&line, st[survey_count].ssid, sizeof(st->ssid));
        next_field(&line, st[survey_count].bssid, sizeof(st->bssid));
        next_field(&line, st[survey_count].security, sizeof(st->security));
        next_field(&line, st[survey_count].siganl, sizeof(st->siganl));
        line = strtok(NULL, "\n");
        st[survey_count].crypto = strstr(st[survey_count].security, "/");
        if (st[survey_count].crypto) {
            *st[survey_count].crypto = '\0';
            st[survey_count].crypto++;
            syslog(LOG_INFO, "Found network - %s %s %s %s %s\n",
                   st[survey_count].channel, st[survey_count].ssid, st[survey_count].bssid, st[survey_count].security, st[survey_count].siganl);
        } else {
            st[survey_count].crypto = "";
        }
        survey_count++;
    }

    if (survey_count == 0 && !print) syslog(LOG_INFO, "No results");
out:
    free(s);
}

#if 1
static struct survey_table* wifi_find_ap(const char *name) {
    int i;

    for (i = 0; i < survey_count; i++) if (!strcmp(name, (char *)st[i].ssid)) return &st[i];

    return 0;
}


#define lengthof(x) (sizeof(x) / sizeof(x[0]))

/* This function is heavily similar to the wifi_repeater_start in
 * net/wifi_core.c from microd (but changed to call ifdown/ifup instead
 * of fiddling with interface configuration manually. */
static void wifi_repeater_start(const char *ifname, const char *staname, const char *channel, const char *ssid,
                                const char *key, const char *enc, const char *crypto) {
    char buf[100];
    int enctype = 0;

    iwpriv(ifname, "Channel", channel);
    //iwpriv(staname, "ApCliEnable", "0");
    if ((strstr(enc, "WPA2PSK") || strstr(enc, "WPAPSKWPA2PSK")) && key) {
        enctype = 1;
        iwpriv(staname, "ApCliAuthMode", "WPA2PSK");
    } else if (strstr(enc, "WPAPSK") && key) {
        enctype = 1;
        iwpriv(staname, "ApCliAuthMode", "WPAPSK");
    } else if (strstr(enc, "WEP") && key) {
        iwpriv(staname, "ApCliAuthMode", "AUTOWEP");
        iwpriv(staname, "ApCliEncrypType", "WEP");
        iwpriv(staname, "ApCliDefaultKeyID", "1");
        iwpriv(staname, "ApCliKey1", key);
        iwpriv(staname, "ApCliSsid", ssid);
    } else if (!key || key[0] == '\0') {
        iwpriv(staname, "ApCliAuthMode", "NONE");
        iwpriv(staname, "ApCliSsid", ssid);
    } else {
        return;
    }

    if (enctype) {
        if (strstr(crypto, "AES") || strstr(crypto, "TKIPAES")) iwpriv(staname, "ApCliEncrypType", "AES");
        else iwpriv(staname, "ApCliEncrypType", "TKIP");
        iwpriv(staname, "ApCliSsid", ssid);
        iwpriv(staname, "ApCliWPAPSK", key);
    }
    iwpriv(staname, "ApCliEnable", "1");
    snprintf(buf, lengthof(buf) - 1, "ifconfig '%s' up", staname);
    system(buf);
}
#endif

int check_assoc(const char *ifname) {
    int socket_id, i;
    struct iwreq wrq;

    socket_id = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(wrq.ifr_ifrn.ifrn_name, ifname);
    ioctl(socket_id, SIOCGIWAP, &wrq);
    close(socket_id);

    for (i = 0; i < 6; i++) if (wrq.u.ap_addr.sa_data[i]) return 1;
    return 0;
}


enum {
    SCAN_DEVICE,
    __SCAN_MAX
};

static const struct blobmsg_policy scan_policy[] = {
    [SCAN_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
};


static int apClient_scan(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    //struct scan_request *hreq;
    struct blob_attr *tb[__SCAN_MAX];
    const char *msgstr;
    void *c, *d;
    int i;

    blobmsg_parse(scan_policy, __SCAN_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[SCAN_DEVICE]) return UBUS_STATUS_INVALID_ARGUMENT;

    msgstr = blobmsg_data(tb[SCAN_DEVICE]);


    wifi_site_survey(msgstr, NULL, 0);

    blob_buf_init(&buf, 0);

    c = blobmsg_open_array(&buf, "results");

    for (i = 0; i < survey_count; i++)
    {
        d = blobmsg_open_table(&buf, NULL);
        blobmsg_add_string(&buf, "ssid", st[i].ssid);
        blobmsg_add_string(&buf, "bssid", st[i].bssid);
        blobmsg_add_string(&buf, "channel", st[i].channel);
        blobmsg_add_string(&buf, "security", st[i].security);
        blobmsg_add_string(&buf, "siganl", st[i].siganl);
        blobmsg_close_table(&buf, d);
    }


    blobmsg_close_array(&buf, c);

    ubus_send_reply(ctx, req, buf.head);

    return UBUS_STATUS_OK;
}

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
        perror("socket error!\n");
        return 0;
    }
    strcpy(ifr.ifr_name, staname);

    if (ioctl(socket_fd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl error\n");
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

    wifi_site_survey(apname, NULL, 0);

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

static void setDefaultSta(char *ifname, char *staname, char *ssid, char *passwd) { 
    int try_count = 0;
    int wait_count = 3;
    while (1) {
        struct survey_table *c;
        wifi_site_survey(ifname, ssid, 0);
        c = wifi_find_ap(ssid);
        try_count++;
        if (c) {
            syslog(LOG_INFO, "Found network, trying to associate (ssid: %s, channel: %s, enc: %s, crypto: %s)\n",
                    c->ssid, c->channel, c->security, c->crypto);

            wifi_repeater_start(ifname, staname, c->channel, c->ssid, passwd, c->security, c->crypto);
            break;
        } else {
            syslog(LOG_INFO, "No signal found to connect to\n");
        }
        if (try_count == 3) break;
        sleep(1);
    }
}

int main(int argc, char **argv)
{
    const char *ubus_socket = NULL;
    if (argc > 3) {
        setDefaultSta(argv[1], argv[2], argv[3], argv[4]);
    }
    uloop_init();
    signal(SIGPIPE, SIG_IGN);

    openlog("rewifi", 0, 0);

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
