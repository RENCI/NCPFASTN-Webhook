import hmac
import os.path
import subprocess
import threading
import graypy
import logging
import socket

from flask import Flask, request, Response


myLogger = logging.getLogger('webhook-listener')
myLogger.setLevel(logging.DEBUG)

grayhandler = graypy.GELFUDPHandler('ncpfast-logs.edc.renci.org', 12201)
myLogger.addHandler(grayhandler)

# handler = logging.StreamHandler(sys.stdout)
# handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
# myLogger.addHandler(handler)

application = Flask(__name__)
application.config['DEBUG'] = True
secretToken = os.getenv('WEBHOOK_TOKEN', 'change_me___preferably_set_in_a_.env_file')
queryToken = os.getenv('QUERY_TOKEN', 'change_me___preferably_set_in_a_.env_file')

myLogger.debug('Token: ' + secretToken + ' Type: ' + str(type(secretToken)))


# handler = logging.StreamHandler(sys.stdout)
# handler.setLevel(logging.DEBUG)
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
# myLogger.addHandler(handler)

# list command name which is a query param in the URL you call and the actual bash commands you want to run,
# and the working directory for the command.


def checkConstraints(cmdDict, payload):
    constraints = cmdDict.get('constraints', None)
    for k, v in constraints.items():
        if k not in payload:
            return False
        if payload[k] != v:
            return False
    return cmdDict


def getBranchOrRelease(payload):
    # build criteria and branch name from GitHub webhook payload
    host = socket.gethostname().split('.')[0]
    ref = payload.get('ref', False)
    release = payload.get('release', False)
    action = payload.get('action', False)
    myLogger.debug(
        '*Determining Type of Webhook*' +
        ' | host: ' + host +
        ' | ref: ' + ref +
        ' | release: ' + release +
        ' | action: ' + action
        )

    # this is pretty inefficient code, but doesn't really matter for this purpose

    # criteria for dev build
    if ref and host == 'ncpfast-dev':  # only push triggers will have the 'ref' element
        branch = os.path.split(ref)[1]

    # criteria for stage build
    elif release and action and host == 'ncpfast-stage':
        if not release['draft']:
            branch = False  # don't build unless is draft
        elif action == 'published':
            branch = False  # don't build if action is published
        else:
            branch = release["tag_name"]

    # criteria for prod build
    elif release and action and host == 'ncpfast':
        if release['draft']:  # don't build drafts
            branch = False
        elif action == 'published':  # only build if published
            branch = release["tag_name"]
        else:
            branch = False

    else:
        branch = False

    myLogger.debug('Determination (Branch or False): ' + branch)
    return branch


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


# flask route/server
@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    # if request.method != 'POST':
    #     myLogger.error('Invalid Method on Webhook')
    #     return Response('Invalid Method', 405)

    # if not request.headers.get('X-Hub-Signature') or not request.args.get('token'):
    #     myLogger.error('No Secret Token Provided in Header or Token Provided as Query Parameter')
    #     return Response('No Secret Token Provided in Header or Token Provided as Query Parameter', 401)

    myLogger.info('Request Received: ' + str(request) + ' ' + str(request.args) + request.get_json())

    if request.args.get('token'):
        token = request.args.get('token')
        myLogger.debug('Token that was passed: ' + token)
        if token == secretToken:
            auth = True
        else:
            auth = False
        myLogger.debug('Auth Result: ' + str(auth))

    elif request.headers.get('X-Hub-Signature'):
        sha, signature = request.headers.get('X-Hub-Signature').split('=')
        auth, authHash = validateSecretToken(signature, request.data, secretToken)

    else:
        auth = False

    if not auth:
        myLogger.error('Webhook: Invalid Token')
        return Response('Unauthorized Authentication Token', 401)

    if not request.get_json():
        myLogger.error('Webhook: Payload empty!')
        return Response('Payload (body) empty! ', 510)

    payload = request.get_json()  # parse webhook request body payload
    branch = getBranchOrRelease(payload)  # validate payload and return the branch to build from or false

    if not branch:
        myLogger.error('Webhook: Payload Error or Build Criteria Not Met')
        return Response('Error parsing the hook payload included below, or this was a draft release or a non-dev '
                        'branch commit and did not trigger a build.\n\n' + str(payload), 510)

    try:
        command = {
            'script': 'export DH_BRANCH=' + branch + ' && docker-compose build --no-cache && docker-compose up -d',
            'dir': '/srv/datahub',
            }
        th = threading.Thread(target=runCommand, args=(command,), daemon=True)
        th.daemon = True
        th.start()
        myLogger.info('Webhook: Accepted, Starting Command Run')
        return Response('Accepted, starting command', 202)

    except (IOError, SystemError) as err:
        myLogger.error('Server Error: ' + err.strerror)
        return Response('Server Error: ' + err.strerror, 500)
