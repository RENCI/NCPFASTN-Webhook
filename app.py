from flask import Flask, request, Response
import os.path
import threading
import hmac
import docker

application = Flask(__name__)
application.config['DEBUG'] = True

secretToken = os.getenv('WEBHOOK_TOKEN', "default")

cmdList = {"rebuild": "Command Details"}


@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    if request.method == 'POST':
        if request.headers('HTTP_X_HUB_SIGNATURE'):
            receivedToken = request.headers('HTTP_X_HUB_SIGNATURE')
            if validateSecretToken(receivedToken):
                if request.args.get('cmd') in cmdList:
                    try:
                        # cmd = request.args.get('cmd')
                        # f = open('_requests.txt', 'w')
                        # f.write(cmd)
                        # f.close()
                        # th = threading.Thread(target=runCommand(cmd))
                        # th.start()
                        return Response('Accepted', 202)
                    except OSError:
                        return Response('Server Error', 500)
                else:
                    return Response('Invalid Command', 418)
            else:
                return Response('Unauthorized Authentication Token', 401)
        else:
            return Response('No Secret Token Provided in Header', 401)
    else:
        return Response('Invalid Method', 405)


def validateSecretToken(receivedToken):
    hashSecret = 'sha1=' + hmac.new(secretToken).hexdigest()
    return hmac.compare_digest(hashSecret, receivedToken)


def runCommand(cmd):
    d = docker.from_env()
    d.build(path='/srv/datahub/webapp')
