import hmac
import os.path
import pprint as pp
import subprocess
import threading
import graypy
import logging
import uuid

from flask import Flask, request, Response


log_setup = logging.getLogger('webhook-listener')
log_setup.setLevel(logging.DEBUG)

handler = graypy.GELFUDPHandler('192.168.16.6', 12201)
log_setup.addHandler(handler)



application = Flask(__name__)
application.config['DEBUG'] = True
secretToken = os.getenv('WEBHOOK_TOKEN', 'change_me___preferably_set_in_a_.env_file')

# list command name which is a query param in the URL you call and the actual bash commands you want to run,
# and the working directory for the command.
cmdList = {
    'rebuild-all':
        {
            'script': 'docker-compose build --no-cache && docker-compose up -d',
            'dir': '/srv/datahub',
            },
    'rebuild-webapp':
        {
            'script': 'docker-compose build --no-cache django && docker-compose up -d django && docker container '
                      'restart nginx',
            'dir': '/srv/datahub'
            }
    }


# flask route/server
@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    myLogger = logging.LoggerAdapter(logging.getLogger('webhook-listener'),
                                     {'trigger-id': str(uuid.uuid4())})
    if request.method != 'POST':
        myLogger.error('Invalid Method on Webhook')
        return Response('Invalid Method', 405)

    if not request.headers.get('X-Hub-Signature'):
        myLogger.error('WebNo Secret Token Provided in Header')
        return Response('No Secret Token Provided in Header', 401)

    sha, signature = request.headers.get('X-Hub-Signature').split('=')
    auth, authHash = validateSecretToken(signature, request.data, secretToken)

    if not auth:
        myLogger.error('Webhook: Invalid Token')
        return Response('Unauthorized Authentication Token', 401)

    if not request.args.get('cmd'):
        myLogger.error('Webhook: No Command Provided')
        return Response('No Command Provided! \nValid Commands: ' + pp.pprint(cmdList), 518)

    cmd = request.args.get('cmd')

    if cmd not in cmdList:
        myLogger.error('Webhook: Command Was Invalid')
        return Response('Command ' + str(cmd) + ' Not Configured! \n Valid Commands:' + pp.pprint(cmdList), 518)

    try:
        command = cmdList[cmd]
        th = threading.Thread(target=runCommand, args=(command,), daemon=True)
        th.daemon = True
        th.start()
        myLogger.info('Webhook: Accepted, Starting Command Run')
        return Response('Accepted, starting command', 202)

    except IOError as err:
        myLogger.error('Server Error: ' + err.strerror)
        return Response('Server Error: ' + err.strerror, 500)


# validates Github token
def validateSecretToken(sig, data, token):
    sig = bytearray(sig, 'utf-8')
    token = bytearray(token, 'utf-8')
    sigSecret = hmac.new(token, msg=data, digestmod='sha1')
    digest = bytearray(sigSecret.hexdigest(), 'utf-8')
    return hmac.compare_digest(digest, sig), digest


# executes a command
def runCommand(command):
    toRun = command['script']
    workDir = command['dir']
    subprocess.call(toRun, cwd=workDir, shell=True)
