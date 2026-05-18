
from flask import Flask, render_template, flash, g, session

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

# In app.py
@app.teardown_appcontext
def close_db(error):
    db_wrapper = g.pop('db_wrapper', None)
    if db_wrapper is not None:
        db_wrapper.close()

def get_db():
    if 'db_wrapper' not in g:
        g.db_wrapper = kaes_database()
    return g.db_wrapper # Return the wrapper so you can call .login()
@app.route('/', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def log_in():
    form = LoginForm()
    if form.validate_on_submit():
        # Use the wrapper to call your login method
        db = get_db()
        if db.login(form.username.data, form.password.data):
            session['user'] = form.username.data
            flash('Successfully logged in!', 'success')
            # return redirect(url_for('dashboard')) # Redirect to a new page
        else:
            flash('Invalid username or password', 'danger')
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", 'danger')
    return render_template('login.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
