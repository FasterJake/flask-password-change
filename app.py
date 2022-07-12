"""Flask app that renders my hmtl and css files
and login/register users to see the homepage
and has an error function built in to do things
with the html"""
# Imports flask and datetime

from datetime import datetime
import os
from string import punctuation


from flask import Flask, render_template, url_for, redirect, flash, request
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

# Sets app and the first template to Flask as __name__
# to search the template folder at default
app = Flask(__name__)
# Creates a database using SQL
db = SQLAlchemy(app)
# Hashes passwords within app
bcrypt = Bcrypt(app)
# Creates random secret key
SECRET_KEY = os.urandom(32)
# Creates the database and uses route
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
# Disables to save memory
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Sets secret key to random 32 characters
app.config["SECRET_KEY"] = "SECRET_KEY"

# Sets login_manager to LoginManager() which holes settings for logging in
login_manager = LoginManager()
# Binds this login_manager to app
login_manager.init_app(app)
# Sets to login function and route to login html
login_manager.login_view = "login"


# At login_manager loads the user
@login_manager.user_loader
def load_user(user_id):
    """Loads the users data, allowing them into webpage"""
    return User.query.get(int(user_id))


# Creates ids(numbers of each person) and puts their
# username and password in the database table
class User(db.Model, UserMixin):
    """Class that creates the database tables"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(18), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class UpdatePasswordForm(FlaskForm):
    password = PasswordField("New Password: ", validators=[DataRequired()])

    submit = SubmitField('Update')


# Class Registration form that uses FlaskForm
# to set requirements of username and password
# as well as creat the boxes/fields to make their inputs
class RegistrationForm(FlaskForm):
    """Class that creates the feilds and functions
    to create a new user"""
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=15)]
                           , render_kw={"placeholder": "Please enter username"})

    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=25)],
                             render_kw={"placeholder": "Enter a password"})

    submit = SubmitField('Register')

    # Function that validates the password
    def validate_password(self, password):
        """"Function that makes sure a password
        is valid by having 1lower/1upper/1digit/1special"""
        # Sets password to field.data to gain access to
        # passwords in the passwordField or database table
        password = password.data
        # Checks if password has 1 lower/1 capital
        # 1 digit and 1 special character inside the password
        # in order to be a valid password

        file = open("C:/Users/Jakes/Desktop/Python stuff/SDEV300/CommonPassword.txt")
        file.readlines()
        if password in file:
            raise ValidationError(print("Way to simple"))

        if (any(char.islower() for char in password)
                and any(char.isupper() for char in password)
                and any(char.isdigit() for char in password)
                and any(char in punctuation for char in password)):

            flash("Password is correct")

        # If requirements not meant, raises an error
        else:
            raise ValidationError(print("Needs at least 1 upper and "
                                        "lowercase letter and 1 number and special character"))

    # Function to check if username already exists
    def validate_username(self, username):
        """Function to make sure that one username
        is not used twice or already exists"""
        # Creates variable for the database to be queried and
        # check for a dupilicate username
        existing_user_username = User.query.filter_by(username=username.data).first()
        # If the username already exists an error is raised
        # along with message
        if existing_user_username:
            raise ValidationError(
                flash('It seems there are two of you, make another one.'))


# Class loginForm that uses FlaskForm to
# log in a user, and uses datarequired()
# to check if the user exists
class LoginForm(FlaskForm):
    """Class loginform to search database
    and log in an existing user"""
    username = StringField(validators=[
        DataRequired(), Length(min=4, max=15)], render_kw={
        "placeholder": "Enter that username"})

    password = PasswordField(validators=[
        DataRequired(), Length(min=12, max=15)], render_kw={
        "placeholder": "Enter your secret "})

    submit = SubmitField('Login')


# Route that sets the authentication page to home
# then prompts user to log in or register
@app.route('/')
@login_required
def logging_in():
    """Function that uses an authentificationpage
    to only allow access into the homepage
    once the user has logged in"""
    return render_template('authentificationpage.html')


# Sets the route to redirect here, and use the html file
# specified as the "homepage" as well as return the current date
@app.route('/scanlanjake_lab6')
@login_required
def homepage():
    """Function to read or render the template html
    and also get the current date"""
    return render_template("scanlanjake_lab6.html", datetime=str(datetime.now()))


# Sets route to login and to get and post data

@app.route("/login", methods=["GET", "POST"])
def login():
    """Function to login an existing user"""
    form = LoginForm()
    # if the form is validate(user exists)
    if form.validate_on_submit():
        # Checks the database for the user
        user = User.query.filter_by(username=form.username.data).first()
        # If user is found
        if user:
            # Hashes the password and logs the user in by
            # redirecting them to the homepage
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("homepage"))
    # If user is not found sends them back to the login page
    return render_template("login.html", form=form)


# Sets route to registration which also gets and posts data
@app.route("/registration", methods=["GET", "POST"])
def register():
    """Function to register a new user"""
    # Sets form to RegistrationForm()
    form = RegistrationForm()
    # If the form follows all specifications
    if form.validate_on_submit():
        # Hashes all the password data
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf8')
         # Creates a new user in the database
        new_user = User(username=form.username.data, password=hashed_password)
        # Adds the user to the database
        db.session.add(new_user)
        # Then applies the changes
        db.session.commit()
        # If all is valid, sends user to login page
        return redirect(url_for("login"))
    # If not valid sends them back to blank registration page
    return render_template("registration.html", form=form)


# Sets route to logout
@app.route('/logout', methods=['GET', 'POST'])
# You have to be logged in, in order to log out
@login_required
def logout():
    """Function to logout the user"""
    # Calls function to logout_user()
    logout_user()
    # Sends user to login page
    return redirect(url_for('login'))


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UpdatePasswordForm()
    userPass = User.query.get(id)
    if request.method == "POST":
        current_user.password = form.password.data


        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html",
                                   form=form,
                                   userPass=userPass,
                                   id=id)
            redirect(url_for('login'))

        except:
            flash("Error! There was a problem changing your password")
            return render_template("update.html",
                                   form=form,
                                   userPass=userPass,
                                   id=id)
            redirect(url_for('update'))
    else:
        return render_template("update.html",
                               form=form,
                               userPass=userPass,
                               id=id)
        redirect(url_for('update'))


# If name is main(as in if main is name essentially)
# then app will run and set debug to true so that the
# program or file can be edited live
if __name__ == "__main__":
    app.run(debug=True)
