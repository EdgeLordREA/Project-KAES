from datetime import timedelta

import flask_session
from flask import Flask, g, session, flash, redirect, url_for
from KAESdatabase import kaes_database
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from blueprints.auth import auth_bp
from blueprints.main import main_bp
from blueprints.user_management import user_management_bp, has_permission

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

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(user_management_bp)


@app.teardown_appcontext
def close_db(error):
    db_wrapper = g.pop('db_wrapper', None)
    if db_wrapper is not None:
        db_wrapper.close()


def get_db():
    if 'db_wrapper' not in g:
        g.db_wrapper = kaes_database()
    return g.db_wrapper


def init_db():
    """Initialize database connection"""
    if 'DATABASE' not in app.config:
        app.config['DATABASE'] = get_db()


# --- Sliding Timer Reset & Live DB Authorization ---
@app.before_request
def load_user_permissions():
    # Initialize database if not already done
    init_db()
    
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
            return redirect(url_for('auth.log_in'))
    return None


# Make has_permission available in templates
app.jinja_env.globals['has_permission'] = has_permission