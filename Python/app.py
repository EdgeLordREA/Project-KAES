from datetime import timedelta

import flask_session
from flask import Flask, render_template, flash, g, session, redirect, url_for
from KAESdatabase import kaes_database
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm
from functools import wraps
app = Flask(__name__)

# --- Session Configurations for a 10-Minute Sliding Window ---
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = "REAKAESCOLLEGE"
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config["SESSION_COOKIE_SECURE"] = True    # Only send over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript from reading the session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" # Protect against CSRF

csrf = CSRFProtect(app)
Session(app)


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                flash("Access denied.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.teardown_appcontext
def close_db(error):
    db_wrapper = g.pop('db_wrapper', None)
    if db_wrapper is not None:
        db_wrapper.close()


def get_db():
    if 'db_wrapper' not in g:
        g.db_wrapper = kaes_database()
    return g.db_wrapper


# --- Sliding Timer Reset & Live DB Authorization ---
@app.before_request
def load_user_permissions():
    if 'user' in session:
        # Refresh the 10-minute sliding cookie timer automatically
        session.permanent = True
        session.modified = True

        db = get_db()
        user_info = db.get_user_permissions(session['user'])

        if user_info:
            # Store data into Flask's global request context 'g'
            g.user_id = user_info['id']
            g.username = session['user']
            g.user_permissions = user_info['permissions']  # This is now a list
        else:
            # Force logout if the user was deleted or altered
            session.clear()
            flash("Your session has expired or account permissions have changed.", "danger")
            return redirect(url_for('log_in'))
    return None


# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def log_in():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        db = get_db()
        if db.login(form.username.data, form.password.data):
            session['user'] = form.username.data
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('log_in'))
    return render_template('dashboard.html')


@app.route('/admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

def has_permission(permission_name):
    if 'user' not in session:
        return False
    if permission_name in g.user_permissions:
        return True
    if 'admin' in g.user_permissions:
        return True
    return False


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('log_in'))