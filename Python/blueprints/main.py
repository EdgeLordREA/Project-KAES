from flask import Blueprint, render_template, flash, session, redirect, url_for, g

main_bp = Blueprint('main', __name__)


@main_bp.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('auth.log_in'))
    return render_template('dashboard.html')
