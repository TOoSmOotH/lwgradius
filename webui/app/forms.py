from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, IntegerField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, IPAddress, ValidationError
import re

class LoginForm(FlaskForm):
    """Form for admin login"""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class UserForm(FlaskForm):
    """Form for creating/editing users"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        EqualTo('password', message='Passwords must match')
    ])
    enable_totp = BooleanField('Enable TOTP Authentication')
    groups = StringField('Groups (comma separated)', validators=[Optional()])
    
    def validate_username(self, field):
        # Username should only contain alphanumeric characters, dots, dashes, and underscores
        if not re.match(r'^[a-zA-Z0-9._-]+$', field.data):
            raise ValidationError('Username can only contain letters, numbers, dots, dashes, and underscores')

class TOTPVerifyForm(FlaskForm):
    """Form for verifying TOTP tokens"""
    token = StringField('TOTP Token', validators=[
        DataRequired(),
        Length(min=6, max=6, message='Token must be 6 digits')
    ])

class ClientForm(FlaskForm):
    """Form for creating/editing RADIUS clients"""
    nasname = StringField('IP Address/Hostname', validators=[DataRequired()])
    shortname = StringField('Short Name', validators=[DataRequired()])
    type = SelectField('Type', choices=[
        ('other', 'Other'),
        ('cisco', 'Cisco'),
        ('juniper', 'Juniper'),
        ('mikrotik', 'MikroTik'),
        ('fortinet', 'Fortinet'),
        ('paloalto', 'Palo Alto'),
        ('checkpoint', 'Check Point')
    ])
    secret = StringField('Shared Secret', validators=[
        DataRequired(),
        Length(min=8, message='Secret must be at least 8 characters')
    ])
    ports = IntegerField('Ports', validators=[Optional()])
    server = StringField('Server', validators=[Optional()])
    community = StringField('Community', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional()])
    
    def validate_nasname(self, field):
        # Check if it's a valid IP address or hostname
        if not re.match(r'^[a-zA-Z0-9.-]+$', field.data):
            raise ValidationError('Invalid IP address or hostname format')

class AdminUserForm(FlaskForm):
    """Form for creating/editing admin users"""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    password = PasswordField('Password', validators=[
        Optional(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        EqualTo('password', message='Passwords must match')
    ])
    email = StringField('Email', validators=[
        Optional(),
        Email()
    ])
    role = SelectField('Role', choices=[
        ('admin', 'Administrator'),
        ('readonly', 'Read Only')
    ])
    
    def validate_username(self, field):
        # Username should only contain alphanumeric characters, dots, dashes, and underscores
        if not re.match(r'^[a-zA-Z0-9._-]+$', field.data):
            raise ValidationError('Username can only contain letters, numbers, dots, dashes, and underscores')

class SearchForm(FlaskForm):
    """Form for searching"""
    query = StringField('Search', validators=[Optional()])
    
class LogFilterForm(FlaskForm):
    """Form for filtering logs"""
    username = StringField('Username', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('', 'All'),
        ('success', 'Success'),
        ('failure', 'Failure')
    ], validators=[Optional()])
    start_date = StringField('Start Date', validators=[Optional()])
    end_date = StringField('End Date', validators=[Optional()])

class ImportUsersForm(FlaskForm):
    """Form for importing users from CSV"""
    csv_data = TextAreaField('CSV Data', validators=[DataRequired()])
    has_header = BooleanField('First row is header', default=True)