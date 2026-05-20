import sqlite3
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, flash, g, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect

from KAESdatabase import kaes_database, initialize_global_tunnel
from flask_session import Session
from forms import CreatePermissionForm
from forms import LoginForm, CreateUserForm

initialize_global_tunnel()
app = Flask(__name__)
GLOBAL_DB_MANAGER = kaes_database()

# region boilerplate
# --- Session Configurations for a 10-Minute Sliding Window ---
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)
app.config["SESSION_TYPE"] = "filesystem"
app.secret_key = "REAKAESCOLLEGE"
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config["SESSION_COOKIE_SECURE"] = True  # Only send over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript from reading the session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protect against CSRF

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
    # Safely releases connection resource back to pool cleanly
    db_wrapper = getattr(g, 'db_wrapper', None)
    if db_wrapper is not None:
        db_wrapper.close_connection()

def get_db() -> kaes_database:
    if 'db_wrapper' not in g:
        # Instantiates the class wrapper pulling an isolated safe cursor link from the pool
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


def has_permission(permission_name):
    if 'user' not in session:
        return False
    if permission_name in g.user_permissions:
        return True
    if 'admin' in g.user_permissions:
        return True
    return False


# pyrefly: ignore [unsupported-operation]
app.jinja_env.globals['permission_required'] = has_permission


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('log_in'))


# endregion
# --- Routes ---

# region Main Routes
@app.route('/', methods=['GET', 'POST'])
def log_in():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        db = get_db()
        if form.username.data and form.password.data:
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


# endregion
# region User Management Routes
@app.route('/user_management', methods=['GET', 'POST'])
@permission_required('manage_users')  # Protect the route!
def user_management():
    if 'user' not in session:
        return redirect(url_for('log_in'))

    db = get_db()
    form = CreateUserForm()

    # Handle user creation
    if form.validate_on_submit():
        try:
            if form.username.data and form.password.data:
                db.add_user(form.username.data, form.password.data)
                flash(f"User '{form.username.data}' created successfully!", "success")
                return redirect(url_for('user_management'))
        except sqlite3.IntegrityError:
            flash("Error creating user. Username already exists.", "danger")
        except ValueError as e:
            flash(f"Error creating user: {str(e)}", "danger")

    # Fetch data to present in template
    all_users = db.get_all_users()
    all_permissions = db.get_all_available_permissions()

    return render_template('user_management.html', form=form, users=all_users, available_permissions=all_permissions)


@app.route('/user_management/delete/<int:user_id>', methods=['POST'])
@permission_required('manage_users')
def delete_user(user_id):
    if g.user_id == user_id:
        flash("You cannot delete your own account!", "danger")
        return redirect(url_for('user_management'))

    db = get_db()

    target_user = next((u for u in db.get_all_users() if u['id'] == user_id), None)
    if target_user and 'admin' in target_user['permissions'] and 'admin' not in g.user_permissions:
        flash("You do not have permission to delete an administrator.", "danger")
        return redirect(url_for('user_management'))

    db.delete_user(user_id)
    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management'))


@app.route('/user_management/update_permissions/<int:user_id>', methods=['POST'])
@permission_required('manage_users')
def update_permissions(user_id):
    import flask
    db = get_db()

    if g.user_id == user_id:
        flash("You cannot alter your own permissions!", "danger")
        return redirect(url_for('user_management'))

    target_user = next((u for u in db.get_all_users() if u['id'] == user_id), None)
    if not target_user:
        flash("User not found.", "danger")
        return redirect(url_for('user_management'))

    if 'admin' in target_user['permissions'] and 'admin' not in g.user_permissions:
        flash("Access denied. You cannot modify a higher-ranking administrator.", "danger")
        return redirect(url_for('user_management'))

    # Read checked parameters from form submission
    selected_perm_ids = flask.request.form.getlist(f'permissions_{user_id}')

    available_perms = db.get_all_available_permissions()

    # SECURITY BACKFILL: Normalize explicitly to integers right away to avoid type-mixing sets
    extended_perm_ids = {int(pid) for pid in selected_perm_ids if pid}

    loop_check = True
    while loop_check:
        loop_check = False
        for perm in available_perms:
            if perm['parent_id'] and int(perm['parent_id']) in extended_perm_ids:
                if int(perm['id']) not in extended_perm_ids:
                    extended_perm_ids.add(int(perm['id']))
                    loop_check = True

    # Validate privilege boundaries using the final calculated array
    for perm in available_perms:
        if int(perm['id']) in extended_perm_ids:
            if perm['name'] not in g.user_permissions:
                flash(f"You cannot grant the '{perm['name']}' permission because you do not have it.", "danger")
                return redirect(url_for('user_management'))

    # Commit the clean structural set back into database persistence
    db.update_user_permissions(user_id, list(extended_perm_ids))
    flash("Permissions updated successfully.", "success")
    return redirect(url_for('user_management'))

# endregion

# region Permission Management
@app.route('/permission_management', methods=['GET', 'POST'])
@permission_required('admin')
def permission_management():
    db = get_db()
    form = CreatePermissionForm()
    all_permissions = db.get_all_permissions()

    if form.validate_on_submit():
        try:
            if form.permission_name.data:
                import flask
                parent_id = flask.request.form.get('parent_id')
                parent_id = int(parent_id) if parent_id and parent_id != "None" else None

                db.create_permission(form.permission_name.data, parent_id)
                flash(f"Permission '{form.permission_name.data}' created!", "success")
                return redirect(url_for('permission_management'))
        except Exception:
            flash("Error creating permission.", "danger")

    import flask
    if flask.request.method == 'POST' and 'update_hierarchy' in flask.request.form:
        perm_id = flask.request.form.get('permission_id')
        parent_id = flask.request.form.get('parent_id')
        parent_id = int(parent_id) if parent_id and parent_id != "None" else None

        if str(perm_id) == str(parent_id):
            flash("A permission cannot be its own parent!", "danger")
        else:
            # pyrefly: ignore [bad-argument-type]
            db.update_permission_hierarchy(int(perm_id), parent_id)
            flash("Hierarchy structural layout adjusted successfully.", "success")
        return redirect(url_for('permission_management'))

    if flask.request.method == 'POST' and 'delete' in flask.request.form:
        permission_id = flask.request.form.get('delete')
        if permission_id:
            db.delete_permission(int(permission_id))
            flash("Permission deleted safely.", "success")
            return redirect(url_for('permission_management'))

    return render_template('permission_management.html', form=form, permissions=all_permissions)


# endregion

if __name__ == '__main__':
    app.run(debug=True)