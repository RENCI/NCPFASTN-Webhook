#!/usr/bin/env bash
exec 1> >(logger -s -t $(basename $0)) 2>&1

source /opt/rh/rh-python36/enable
pipenv install && echo "Pipenv activated"
pipenv run gunicorn wsgi:application --bind 0.0.0.0:5656 --workers 2 --daemon --reload --access-logfile '/srv/webhook/access.log' && echo "Gunicorn Running"