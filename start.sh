#!/bin/bash
interface=${1:-"wlan0"}

ps aux|grep flask|grep -v grep > /dev/null && killall flask

if [[ ! $(ifconfig $interface|grep UP) ]]
then
    sudo -s -- 'iwconfig $interface mode monitor && ifconfig $interface up'
fi

FLASK_APP=frontend.py flask run --host 0.0.0.0 &
sudo python backend.py $interface
