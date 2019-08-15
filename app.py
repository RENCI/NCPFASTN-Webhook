import hmac
import os.path
import pprint as pp
import subprocess
import threading

from flask import Flask, request, Response


application = Flask(__name__)
application.config['DEBUG'] = True
secretToken = os.getenv('WEBHOOK_TOKEN', 'change_me___preferably_set_in_a_.env_file')

# list command name and the actual bash commands you want to run
# do not include any sensitive information as this list will be displayed for assistance
cmdList = {
    'rebuild-all':
        {
            'script': 'docker-compose build --no-cache && docker-compose up -d',
            'dir': '/srv/datahub',
            },
    'rebuild-webapp':
        {
            'script': 'docker-compose build --no-cache django && docker-compose up -d',
            'dir': '/srv/datahub'
            }
    }


# flask route/server
@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    if request.method != 'POST':
        return Response('Invalid Method', 405)

    if not request.headers.get('X-Hub-Signature'):
        return Response('No Secret Token Provided in Header', 401)

    sha, signature = request.headers.get('X-Hub-Signature').split('=')
    auth, authHash = validateSecretToken(signature, request.data, secretToken)

    if not auth:
        return Response('Unauthorized Authentication Token', 401)

    if not request.args.get('cmd'):
        return Response('No Command Provided! \nValid Commands: ' + pp.pprint(cmdList), 518)

    cmd = request.args.get('cmd')

    if cmd not in cmdList:
        return Response('Command ' + str(cmd) + ' Not Configured! \n Valid Commands:' + pp.pprint(cmdList), 518)

    try:
        command = cmdList[cmd]
        th = threading.Thread(target=runCommand, args=(command,), daemon=True)
        th.daemon = True
        th.start()
        return Response('Accepted, starting command', 202)

    except IOError as err:
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
