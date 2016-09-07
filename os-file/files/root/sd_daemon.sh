#!/bin/sh


while true
do 
    echo "wait for mounting sd card"
    while [ ! -f /tmp/run/mountd/mmcblk0p1/autorun ]; do
        sleep 1
    done

    echo "run autorun script on sd card"
    sh /tmp/run/mountd/mmcblk0p1/autorun &

    echo "wait for removing sd card"
    while [ -f /tmp/run/mountd/mmcblk0p1/autorun ]; do
        sleep 3
    done
done
