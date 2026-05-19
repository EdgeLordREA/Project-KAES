from flask import Blueprint, render_template, flash, session, redirect, url_for, g
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/', methods=['GET', 'POST'])
def log_in():
    if 'user' in session:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        from flask import current_app
        db = current_app.config['DATABASE']
        if db.login(form.username.data, form.password.data):
            session['user'] = form.username.data
            flash('Successfully logged in!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.log_in'))
