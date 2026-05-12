
from flask import Flask, render_template, flash, g

from KAESdatabase import kaes_database
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

from forms import LoginForm

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False # Session expires when the browser closes
app.config["SESSION_TYPE"] = "filesystem" # Store session data on the server's file system
app.secret_key = "REAKAESCOLLEGE" # Secure the session with a secret key
app.config['SESSION_USE_SIGNER'] = True  # Sign session IDs for security
csrf = CSRFProtect(app)
Session(app)

def get_db():
    if 'db' not in g:
        # Initialize your class
        g.db_wrapper = kaes_database()
        g.db = g.db_wrapper.get_connection()
    return g.db

@app.route('/', methods=['GET', 'POST'])
def log_in():  # put application's code here
    form = LoginForm()
    if form.validate_on_submit():
        print(form.username.data + " " + form.password.data)
        return "Login successful"
    if form.errors:
        for error in form.errors:
            flash(error)
    return render_template('login.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
