from flask import Flask, request, Response
import os.path
import subprocess
import threading
import hmac
import docker
import pprint as pp


application = Flask(__name__)

application.config['DEBUG'] = True

secretToken = os.getenv('WEBHOOK_TOKEN', "default")

cmdList = {"rebuild": "docker-compose build --no-cache && docker-compose up -d"}


@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    if request.method != 'POST':
        return Response('Invalid Method', 405)

    if not request.headers.get('X-Hub-Signature'):
        return Response('No Secret Token Provided in Header', 401)

    sha, signature = request.headers.get('X-Hub-Signature').split('=')
    auth, hash = validateSecretToken(signature, request.data, secretToken)
    if not auth:
        return Response('Unauthorized Authentication Token', 401)

    if not request.args.get('cmd'):
        return Response('No Command Provided! \nValid Commands: ' + pp.pprint(cmdList), 518)

    cmd = request.args.get('cmd')
    if cmd not in cmdList:
        return Response('Command ' + str(cmd) + ' Not Configured! \n Valid Commands:' + pp.pprint(cmdList), 518)
    try:
        # f = open('_requests.txt', 'w')
        # f.write(cmd)
        # f.close()
        th = threading.Thread(target=runCommand, args=(cmd,), daemon=True)
        th.daemon = True
        th.start()
        return Response('Accepted, starting command', 202)
    except IOError as err:
        return Response('Server Error: ' + err.strerror, 500)


def validateSecretToken(sig, data, secretToken):
    sig = bytearray(sig, 'utf-8')
    secretToken = bytearray(secretToken, 'utf-8')
    sigSecret = hmac.new(secretToken, msg=data, digestmod='sha1')
    digest = bytearray(sigSecret.hexdigest(), 'utf-8')
    print(digest)
    return hmac.compare_digest(digest, sig), digest


def runCommand(cmd):
    toRun = cmdList[cmd]
    subprocess.call(toRun, cwd='/srv/datahub', shell=True)
