#!/usr/bin/env bash
exec 1> >(logger -s -t $(basename $0)) 2>&1

source /opt/rh/rh-python36/enable
pipenv run kill -9 `ps -A -F | grep 'gunicorn wsgi:application'`
