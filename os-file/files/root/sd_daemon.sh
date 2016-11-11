#!/bin/sh


while true
do 
    echo "wait for mounting sd card"
    while [ ! -b /dev/mmcblk0p1 ]; do
        sleep 3
    done

    if [ -f /tmp/run/mountd/mmcblk0p1/autorun ]; then
        echo "run autorun script on sd card" > /dev/console
        sh /tmp/run/mountd/mmcblk0p1/autorun &
    fi 

    echo "wait for unmounting sd card"
    while [ -b /dev/mmcblk0p1 ]; do
        sleep 6
    done
done

