from flask import Flask
from flask_session import Session

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False # Session expires when the browser closes
app.config["SESSION_TYPE"] = "filesystem" # Store session data on the server's file system
app.secret_key = "REAKAESCOLLEGE" # Secure the session with a secret key
app.config['SESSION_USE_SIGNER'] = True  # Sign session IDs for security
Session(app)


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
