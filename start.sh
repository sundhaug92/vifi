#!/bin/bash
killall flask
FLASK_APP=frontend.py flask run --host 0.0.0.0 &
sudo python backend.py
