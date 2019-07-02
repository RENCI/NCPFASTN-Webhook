from flask import Flask, request, Response
import os.path
import threading


application = Flask(__name__)

token = os.getenv('WEBHOOK_TOKEN', "default")

cmdList = {"name": "Command Details"}


@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    for i in request.args.post():
        print(i)
    if request.args.get('token', '') == token:
        if request.args.get('cmd', '') in cmdList:
            try:
                cmd = request.args.get('cmd')
                f = open('_requests.txt', 'w')
                f.write(cmd)
                f.close()
                th = threading.Thread(target=runCommand(cmd))
                th.start()
                return Response('Accepted', 202)
            except OSError:
                return Response('Server Error', 500)
        else:
            return Response('Invalid Command', 418)
    else:
        return Response('Unauthorized Authentication Token', 401)

# else:
# return Response('Invalid HTTP Method', 405)


def runCommand(cmd):
    print("trying to do this command name: " + cmd)
