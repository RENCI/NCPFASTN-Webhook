import hmac
import os.path
import pprint as pp
import subprocess
import threading
import graypy
import logging
import uuid
import yaml

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

with open('/projects/ncpfast/_settings/webhook.yaml') as f:
    settings = yaml.load(f, Loader=yaml.FullLoader)


cmdList = settings['commands']


# flask route/server
@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    myLogger = logging.LoggerAdapter(logging.getLogger('webhook-listener'),
                                     {'trigger-id': str(uuid.uuid4())})
    if request.method != 'POST':
        myLogger.error('Invalid Method on Webhook')
        return Response('Invalid Method', 405)

    if not request.headers.get('X-Hub-Signature') or request.args.get('token'):
        myLogger.error('No Secret Token Provided in Header or Token Provided as Query Parameter')
        return Response('No Secret Token Provided in Header', 401)

    if request.headers.get('X-Hub-Signature'):
        sha, signature = request.headers.get('X-Hub-Signature').split('=')
        auth, authHash = validateSecretToken(signature, request.data, secretToken)
    elif request.args.get('token'):
        token = request.args.get('token')
        auth = validateQueryToken()
    else:
        auth = False

    if not auth:
        myLogger.error('Webhook: Invalid Token')
        return Response('Unauthorized Authentication Token', 401)

    if not request.args.get('cmd'):
        myLogger.error('Webhook: No Command Provided')
        return Response('No Command Provided! \nValid Commands: ' + pp.pprint(cmdList), 518)

    cmd_req = request.args.get('cmd')

    if cmd_req not in cmdList:
        myLogger.error('Webhook: Command Was Invalid')
        return Response('Command ' + str(cmd_req) + ' Not Configured! \n Valid Commands:' + pp.pprint(cmdList), 518)

    payload = request.get_json()
    command = cmdList[cmd_req]
    if not checkConstraints(command, payload):
        myLogger.error('Webhook: Constraint Failed')
        return Response('Predefined constraints were not met, skipping command ' + str(command), 510)

    try:
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


# validate token passed at query parameter
def validateQueryToken(token):
    if token == secretToken:
        return True
    else:
        return False


def checkConstraints(cmdDict, payload):
    constraints = cmdDict.get('constraints', None)
    for k, v in constraints.items():
        if k not in payload:
            return False
        if payload[k] != v:
            return False
    return cmdDict


# executes a command
def runCommand(command):
    toRun = command['command']
    workDir = command['dir']
    subprocess.call(toRun, cwd=workDir, shell=True)
