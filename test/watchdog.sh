#!/bin/sh

PROC_NAME=test_process


while true; do
    server=`ps aux | grep ${PROC_NAME} | grep -v grep`
    if [ ! "$server" ]; then
        ./test_process &
        echo "starting process"
        sleep 3
    fi
    sleep 5 # avoid create many process
done
