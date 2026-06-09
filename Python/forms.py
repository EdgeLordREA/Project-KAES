from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.fields.choices import SelectField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    submit = SubmitField('Login')


class CreatePermissionForm(FlaskForm):
    permission_name = StringField('Permission Name', validators=[DataRequired(), Length(min=3, max=25)])
    # We will dynamically populate choices in the route
    submit = SubmitField('Create Permission')


class CreateExamForm(FlaskForm):
    exam_name = StringField('Exam Name', validators=[DataRequired(), Length(min=3, max=25)])
    exam_description = StringField('Exam Description', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Create Exam')


class CreateQuestionForm(FlaskForm):
    question_text = StringField('Question Text', validators=[DataRequired(), Length(min=10, max=500)])
    category = SelectField('Category', validators=[DataRequired()])
    modifier = IntegerField('Modifier', validators=[DataRequired()])
    submit = SubmitField('Create Question')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=25)])
    user_group = SelectField('Group', coerce=int, validators=[])  # Will be populated dynamically
    submit = SubmitField('Create User')


class CreateGroupForm(FlaskForm):
    group_name = StringField('Group Name', validators=[DataRequired(), Length(min=3, max=45)])
    submit = SubmitField('Create Group')


class UpdateUserGroupForm(FlaskForm):
    user_group = SelectField('Group', coerce=int, validators=[])
    submit = SubmitField('Update Group')
