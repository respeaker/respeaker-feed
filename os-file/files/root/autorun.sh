#!/bin/sh

echo "autorun"
echo "autorun" > /dev/console
echo "started" > /tmp/autorun

amixer sset Capture 95%
amixer sset Headphone 85%
amixer sset Speaker 80%

/root/sd_daemon.sh &


