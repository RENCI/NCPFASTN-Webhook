from flask import Flask, request, Response
import os.path

application = Flask(__name__)

token = os.getenv('WEBHOOK_TOKEN', "default")


@application.route('/webhook', methods=['POST', 'GET'])
def webhook():
    if request.method == 'POST':
        if request.get_json(force=True):
            payload = request.get_json(force=True)
            if payload.get("token"):
                if payload['token'] == token:
                    f = open('_requests.txt', 'w')
                    f.write(payload['app'])
                    f.close()
                    return Response('Accepted', 202)
                else:
                    return Response('Unauthorized Authentication Token', 401)
            else:
                return Response('No Authentication Token Sent', 401)
        else:
            return Response('Incorrect Request Syntax', 400)
    else:
        return Response('Invalid Method', 405)

