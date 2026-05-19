from flask import Blueprint, render_template, flash, session, redirect, url_for, g, request
from functools import wraps
from forms import CreateUserForm

user_management_bp = Blueprint('user_management', __name__, url_prefix='/user_management')


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                flash("Access denied.", "danger")
                return redirect(url_for('main.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def has_permission(permission_name):
    if 'user' not in session:
        return False
    if permission_name in g.user_permissions:
        return True
    if 'admin' in g.user_permissions:
        return True
    return False


@user_management_bp.route('', methods=['GET', 'POST'])
@permission_required('admin')
def user_management():
    if 'user' not in session:
        return redirect(url_for('auth.log_in'))

    from flask import current_app
    db = current_app.config['DATABASE']
    form = CreateUserForm()

    # Handle user creation
    if form.validate_on_submit():
        try:
            db.add_user(form.username.data, form.password.data)
            flash(f"User '{form.username.data}' created successfully!", "success")
            return redirect(url_for('user_management.user_management'))
        except Exception as e:
            flash("Error creating user. Username might already exist.", "danger")

    # Fetch data to present in template
    all_users = db.get_all_users()
    all_permissions = db.get_all_available_permissions()

    return render_template('user_management.html', form=form, users=all_users, available_permissions=all_permissions)


@user_management_bp.route('/delete/<int:user_id>', methods=['POST'])
@permission_required('admin')
def delete_user(user_id):
    # Prevent an admin from deleting themselves accidentally
    if g.user_id == user_id:
        flash("You cannot delete your own account!", "danger")
        return redirect(url_for('user_management.user_management'))

    from flask import current_app
    db = current_app.config['DATABASE']
    db.delete_user(user_id)
    flash("User deleted successfully.", "success")
    return redirect(url_for('user_management.user_management'))


@user_management_bp.route('/update_permissions/<int:user_id>', methods=['POST'])
@permission_required('admin')
def update_permissions(user_id):
    import flask  # To grab raw request form values
    from flask import current_app
    db = current_app.config['DATABASE']

    # Get all checked permission checkboxes for this specific user
    # HTML input names will be structured like: permissions_{{ user_id }}
    selected_perms = flask.request.form.getlist(f'permissions_{user_id}')

    db.update_user_permissions(user_id, selected_perms)
    flash("Permissions updated successfully.", "success")
    return redirect(url_for('user_management.user_management'))
