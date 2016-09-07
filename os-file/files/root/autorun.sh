#!/bin/sh

echo "autorun"
echo "autorun" > /dev/console
echo "started" > /tmp/autorun

/root/sd_daemon.sh &


