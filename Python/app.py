from datetime import timedelta

import flask_session
from flask import Flask, render_template, flash, g, session, redirect, url_for
from KAESdatabase import kaes_database
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, CreateUserForm
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


@app.route('/user_management', methods=['GET', 'POST'])
@permission_required('admin')  # Protect the route!
def user_management():
    if 'user' not in session:
        return redirect(url_for('log_in'))

    db = get_db()
    form = CreateUserForm()

    # Handle user creation
    if form.validate_on_submit():
        try:
            db.add_user(form.username.data, form.password.data)
            flash(f"User '{form.username.data}' created successfully!", "success")
            return redirect(url_for('user_management'))
        except Exception as e:
            flash("Error creating user. Username might already exist.", "danger")

    # Fetch data to present in template
    all_users = db.get_all_users()
    all_permissions = db.get_all_available_permissions()

    return render_template('user_management.html', form=form, users=all_users, available_permissions=all_permissions)


@app.route('/user_management/delete/<int:user_id>', methods=['POST'])
@permission_required('admin')
def delete_user(user_id):
    # Prevent an admin from deleting themselves accidentally
    if g.user_id == user_id:
        flash("You cannot delete your own account!", "danger")
        return redirect(url_for('user_management'))

    db = get_db()
    db.delete_user(user_id)
    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management'))


@app.route('/user_management/update_permissions/<int:user_id>', methods=['POST'])
@permission_required('admin')
def update_permissions(user_id):
    import flask  # To grab raw request form values
    db = get_db()

    # Get all checked permission checkboxes for this specific user
    # HTML input names will be structured like: permissions_{{ user_id }}
    selected_perms = flask.request.form.getlist(f'permissions_{user_id}')

    db.update_user_permissions(user_id, selected_perms)
    flash("Permissions updated successfully.", "success")
    return redirect(url_for('user_management'))


def has_permission(permission_name):
    if 'user' not in session:
        return False
    if permission_name in g.user_permissions:
        return True
    if 'admin' in g.user_permissions:
        return True
    return False
app.jinja_env.globals['permission_required'] = has_permission

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('log_in'))