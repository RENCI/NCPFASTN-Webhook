# this file is scheduled to be run every minute in the crontab,
# and will loop for no longer than one minute before self-executing.

import os
import datetime
import time

COMMANDS = {
    'django': 'cd /usr/datahub && docker-compose up -d --build'
}

filename = '/usr/webhook/_requests.txt'

start = time.time()
end = 60 + start
while time.time() < end:
    requestsFile = open(filename, 'r')
    lines = requestsFile.readlines()
    if len(lines) >= 1:
        for line in lines:
            if line in COMMANDS:
                cmd = COMMANDS[line]
                os.system(cmd)
        requestsFile.close()
        open(filename, 'w').truncate(0)
    else:
        requestsFile.close()
        time.sleep(5)

