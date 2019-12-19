import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from tempfile import mkdtemp
from helpers import turn_into_dictionary, weather, random_generator
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import json
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Configures the application
app = Flask(__name__)
app.secret_key = "codigosecreto666$$$"


# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configures the email sending
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_DEBUG"] = False
app.config["MAIL_USERNAME"] = "MyOnlineAgendaCS50@gmail.com"
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = "MyOnlineAgendaCS50@gmail.com"
app.config["MAIL_MAX_EMAILS"] = None
app.config["MAIL_ASCII_ATTACHMENTS"] = False
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)


# Configures the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agenda.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.String(10), unique=False, nullable=False)
    email = db.Column(db.String(345), unique=True, nullable=False)
    show_done = db.Column(db.Boolean, nullable=False, default=True)
    token = db.Column(db.String(16), nullable=True, default=None)
    specific = db.relationship("SpecificTasks", backref="owner")
    daily = db.relationship("DailyTasks", backref="owner")


class SpecificTasks(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    date = db.Column(db.String(20), nullable=False)
    task = db.Column(db.String(255), nullable=False)
    done = db.Column(db.Boolean, nullable=False, default=False)


class DailyTasks(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task = db.Column(db.String(255), nullable=False)
    done = db.Column(db.Boolean, nullable=False, default=False)
    last_updated = db.Column(db.String(10), nullable=False)


# This initiates the log in manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.unauthorized_handler
def unauthorized():
    flash("Must be logged in in order to perform that action")
    return redirect("/error")


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# Manages all the flashed error messages
@app.route("/error")
def error():
    return render_template("error.html")


# Logs out the user
@app.route("/logout", methods = ["GET"])
@login_required
def logout():
    logout_user()
    return redirect("/login")


# Allows the user to log in
@app.route("/login", methods = ["GET", "POST"])
def login():

    # Clears the session in order to log in
    session.clear()

    # Shows the log in screen
    if request.method == "GET":
        return render_template("login.html")

    # Performs the log in operation
    else:
        # Ensures proper usage
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember")

        if not username or not password:
            flash("Must fill all forms.")
            return redirect("/error")

        # Checks if the user exists in the database
        user = Users.query.filter_by(username=username).first()
        if user:
            # Checks if the password is correct, logging the user in
            if check_password_hash(user.password, password):
                if remember == "on":
                    login_user(user, remember=True)
                if not remember:
                    login_user(user, remember=False)
                return redirect("/")
            else:
                flash("Incorrect password")
                return redirect("/error")
        # Username is not registered
        else:
            flash("Username is not registered.")
            return redirect("/error")


# This allow new users to register
@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email = request.form.get("email")

        # Ensures proper usage
        if not username or not password or not confirmation or not email:
            flash("Must fill all forms.")
            return redirect("/error")
        if password != confirmation:
            flash("Passwords don't match.")
            return redirect("/error")

        # Checks that the username meets the required criteria
        if 4 > len(username) > 10:
            flash("Username must be between 4 and 10 characters long.")
            return redirect("/error")

        # This ensures that the password meets the required criteria
        if password:
            error_message = "Password format incorrect, must have at least one uppercase, one lowercase and numbers with a minimal length of 4 characters."
            if not any(x.isupper() for x in password):
                flash(error_message)
                return redirect("/error")
            elif not any(x.islower() for x in password):
                flash(error_message)
                return redirect("/error")
            elif not any(x.isdigit() for x in password):
                flash(error_message)
                return redirect("/error")
            elif len(password) < 4:
                flash(error_message)
                return redirect("/error")

        # Checks whether the username or the email are already taken or not
        check_username = Users.query.filter_by(username=username).first()
        check_email = Users.query.filter_by(email=email).first()
        if check_username:
           flash("Username already taken.")
           return redirect("/error")
        if check_email:
           flash("Email already taken.")
           return redirect("/error")

        # This sends the confirmation email
        if not check_username and not check_email:
            # This creates a dictionary with all the users registry data in order to send it via a the token in the validation process
            user_data = {
                "username" : username,
                "password" : generate_password_hash(password),
                "email" : email
            }
            # This creates the token
            token = s.dumps(user_data, salt="user-data")

            # This creates and send the email with the token
            msg = Message("Confirm your account", sender="MyOnlineAgendaCS50@gmail.com", recipients=[email])
            confirmation_link = url_for("confirm_account", token=token, _external=True)
            msg.body = "Your validation link is <a href={}>here</a>.\nPlease be sure to use within the next 15 minutes as it will expire and you will need to register again.".format(confirmation_link)
            mail.send(msg)
        return redirect("/login")


# This confirm the users data entered when registering
@app.route("/confirm_account/<token>", methods = ["GET"])
def confirm_account(token):
    try:
        # This gets the data from the token, which is a dictionary containing all the necesary data regarding the user in order to store it in the database
        data = s.loads(token, salt="user-data", max_age=900)
        user= Users(username=data.get("username"), password=data.get("password"), email=data.get("email"))
        check_username = Users.query.filter_by(username=data.get("username")).first()
        check_email = Users.query.filter_by(email=data.get("email")).first()
        if not check_username and not check_email:
            db.session.add(user)
            db.session.commit()
        if check_username:
            flash("Username already taken. You validated your account too late and someone else is using that username or you already validated your account.")
            return redirect("/error")
        elif check_email:
            flash("Email already taken. You validated your account too late and someone else is using that email or you already validated your account.")
            return redirect("/error")
        return redirect ("/login")
    except SignatureExpired:
        flash("Your link expired. You must use it within 15 minutes after registering.")
        return redirect("/error")
    except BadTimeSignature:
        flash("Your validation link is wrong.")
        return redirect("/error")


# This shows the index
@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/weatherlat=<lat>lng=<lng>")
@login_required
def get_weather(lat, lng):
    print(weather(lat, lng))
    return jsonify(weather(lat, lng))


# This route is used to check for usernames or emails according to AJAX requests
@app.route("/check/<username>/<email>")
def check(username, email):
    # This is for the email AJAX request, returns true if the email is avaliable
    if username == "nouser":
        check = Users.query.filter_by(email=email).all()
        if check:
            return jsonify(False)
        else:
            return jsonify(True)

    # This is for the username AJAX request, returns true if the username is avaliable
    elif email == "noemail":
        check = Users.query.filter_by(username=username).all()
        if check:
            return jsonify(False)
        else:
            return jsonify(True)

    # This is for the register validation form AJAX request, returns true if both email and username are avaliable
    else:
        check_username= Users.query.filter_by(username=username).all()
        check_email = Users.query.filter_by(email=email).all()
        if not check_username and not check_email:
            return jsonify(True)
        else:
            return jsonify(False)


# This saves a specific task according to its date
@app.route("/specifictask=<specific_task>date=<specific_date>", methods = ["GET"])
@login_required
def save_specific_task(specific_task, specific_date):
    new_task = SpecificTasks(owner_id=current_user.get_id(), date=specific_date, task=specific_task, done=False)
    db.session.add(new_task)
    db.session.commit()
    return redirect("/")



# This gets all the specific tasks according to the date sent by an AJAX request and if there are no task returns False
@app.route("/specific/<date>", methods=["GET"])
@login_required
def get_specific_task(date):

    # If no results for that date, returns False
    result = SpecificTasks.query.filter_by(owner_id=current_user.get_id(), date=date).all()
    if not result:
        return jsonify(False)
    else:
        # This will show the tasks according to the user's choice of seeing all tasks or only those who are undone
        if current_user.show_done:
            return jsonify(turn_into_dictionary(result))
        else:
            undone_tasks = SpecificTasks.query.filter_by(owner_id=current_user.get_id(), date=date, done=False).all()
            if undone_tasks:
                return jsonify(turn_into_dictionary(undone_tasks))
            else:
                return jsonify("notasks")


# This updates a specific task to "done" (True) according to the "id" sent by an AJAX request
@app.route("/specific//<specific_id>")
@login_required
def specific_task_done(specific_id):
    task = SpecificTasks.query.filter_by(owner_id=current_user.get_id(), id=specific_id).first()
    if task.done == False:
        task.done = True
        db.session.commit()
        return redirect("/")


# This updates the daily tasks database using an AJAX request in order to reset them if the dates
# in the last_updated column and the current one dont match
@app.route("/update_daily_tasks<date>", methods=["GET"])
@login_required
def update_daily_tasks(date):
    tasks = DailyTasks.query.filter_by(owner_id=current_user.get_id()).all()
    if tasks:
        for task in tasks:
            if task.last_updated != date:
                task.last_updated = date
                task.done = False
                db.session.commit()
    return redirect("/")


# This saves a daily task into the database
@app.route("/dailytask=<task>date=<date>", methods=["GET"])
@login_required
def daily(task, date):
        if not task:
            flash("Must input a task")
            return redirect("/error")
        elif not date:
            flash("Must input a date")
            return redirect("/error")
        new_task = DailyTasks(owner_id=current_user.get_id(), task=task, last_updated=date)
        db.session.add(new_task)
        db.session.commit()
        return redirect("/")


# This shows all the daily tasks
@app.route("/daily/")
@login_required
def show_daily_tasks():
    tasks = DailyTasks.query.filter_by(owner_id=current_user.get_id()).all()
    if not tasks:
        return jsonify(False)
    else:
        # This will show the tasks according to the user's choice of seeing all tasks or only those who are undone
        if current_user.show_done:
            return jsonify(turn_into_dictionary(tasks))
        else:
            undone_tasks = DailyTasks.query.filter_by(owner_id=current_user.get_id(), done=False).all()
            if undone_tasks:
                return jsonify(turn_into_dictionary(undone_tasks))
            else:
                return jsonify("notasks")

# This turns a daily task into "done" (True) according to an "id" sent by an AJAX request
@app.route("/daily//id=<daily_id>date=<date>")
@login_required
def daily_task_done(daily_id, date):
    task = DailyTasks.query.filter_by(owner_id = current_user.get_id(), id = daily_id).first()
    if not task:
        flash("No task found")
        redirect("/error")
    if task.done == False:
        task.last_updated = date
        task.done = True
        db.session.commit()
        return redirect("/")


# This enables the user to change details regarding to his account
@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")
    else:
        username = request.form.get("username")
        email = request.form.get("email")
        old_password = request.form.get("old_password")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        user = Users.query.filter_by(id=current_user.get_id()).first()

        # Looks up for the users data
        check = Users.query.filter_by(id=current_user.get_id()).first()

        # Checks the users password
        if not old_password:
            logout_user()
            flash("In order to make any change you must input your password")
            return redirect("/error")
        else:
            if check_password_hash(check.password, old_password):
                # This creates a dictionary to be sent with the token
                dictionary ={}
                dictionary["user_id"] = current_user.get_id()

                # Updates the username
                if username:
                    #Checks if the username is not already taken
                    check_username = Users.query.filter_by(username=username).first()
                    if not check_username:

                        # This adds the username to the dictionary
                        dictionary["username"] = username

                    else:
                        # Username already used, returns error
                        flash("Username already taken.")
                        return redirect("/error")

                # Updates the email
                if email:

                    # Checks if the email is not already used
                    check_email = Users.query.filter_by(email=email).first()
                    if not check_email:

                        # This adds the email to the dictionary
                        dictionary["email"] = email

                    else:
                        # Email already used, returns error
                        flash("Email already taken.")
                        return redirect("/error")

                # Updates the password
                if password:
                    error_message = "Password format incorrect, must have at least one uppercase, one lowercase and numbers with a minimal length of 4 characters."
                    # Ensures proper usage
                    if not password or not confirmation or not old_password:
                        flash("Must fill all password forms.")
                        return redirect("/error")
                    # Checks if the new passwords match
                    if password != confirmation:
                        flash("New and confirmation passwords must match")
                        return redirect("/error")

                    # This ensures that the password meets the required criteria
                    if not any(x.isupper() for x in password):
                        flash(error_message)
                        return render_template("error.html")
                    elif not any(x.islower() for x in password):
                        flash(error_message)
                        return render_template("error.html")
                    elif not any(x.isdigit() for x in password):
                        flash(error_message)
                        return render_template("error.html")
                    elif len(password) < 4:
                        flash(error_message)
                        return render_template("error.html")

                    # This adds the password to the dictionary
                    dictionary["password"] = generate_password_hash(password)

                # This creates the token
                random = random_generator()
                dictionary["token"] = random
                token = s.dumps(dictionary, salt="change-data")
                check.token = random
                db.session.commit()

                # This creates and send the email with the token
                msg = Message("Confirm your changes in your account", sender="MyOnlineAgendaCS50@gmail.com", recipients=[user.email])
                confirmation_link = url_for("confirm_changes", token=token, _external=True)
                msg.body = "Your validation link is <a href={}>here</a>.\nPlease be sure to use within the next 15 minutes as it will expire and you will need to register again.".format(confirmation_link)
                mail.send(msg)

                return redirect("/login")

            else:
                logout_user()
                flash("The password you entered is incorrect")
                return redirect("/error")

@app.route("/confirm_changes/<token>", methods=["GET"])
def confirm_changes(token):
    try:
        changes = s.loads(token, salt="change-data", max_age=900)
        user = Users.query.filter_by(id=changes.get("user_id")).first()

        # This resets the user token in order to make the validation link only usable once during its lifetime
        if user.token:
            if user.token == changes.get("token"):
                user.token = None
                db.session.commit()

                # This ensures that the data was not used in case someone registers with the same data before the user can confirm the changes
                if changes.get("username"):
                    check_username = Users.query.filter_by(username=changes.get("username")).first()
                    if not check_username:
                        user.username = changes.get("username")
                        db.session.commit()
                    else:
                        flash("Username already taken. You validated your account too late and someone else is using that username or you already validated your account.")
                        return redirect("/error")
                if changes.get("password"):
                    user.password = changes.get("password")
                    db.session.commit()
                if changes.get("email"):
                    check_email = Users.query.filter_by(username=changes.get("email")).first()
                    if not check_email:
                        user.email = changes.get("email")
                        db.session.commit()
                    else:
                        flash("Email already taken. You validated your account too late and someone else is using that email or you already validated your account.")
                        return redirect("/error")
            else:
                flash("Tokens don't match. Generate a new validation link.")
        else:
            flash("You already used this validation link. Make another one.")
            return redirect("/error")
    except SignatureExpired:
        flash("Your link expired. You must use it within 15 minutes after registering.")
        return redirect("/error")
    except BadTimeSignature:
        flash("Your validation link is wrong.")
        return redirect("/error")
    return redirect("/login")

# This allows to check the users option "show done tasks"
@app.route("/show_done", methods=["GET"])
@login_required
def show():
    return jsonify(current_user.show_done)

# This allows to switch between seeing all tasks and only those who are not done yet
@app.route("/show_done/<value>", methods=["GET"])
@login_required
def show_done(value):
    try:
        value = json.loads(value)
        result = Users.query.filter_by(id=current_user.get_id()).first()
        result.show_done = value
        db.session.commit()
        return redirect("/")
    except ValueError:
        flash("Invalid input.")
        return redirect("/error")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    else:
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensures proper usage
        if not username or not email or not password or not confirmation:
            flash("Must fill all forms.")
            return redirect("/error")
        if not password or not confirmation:
            flash("Must fill all password forms.")
            return redirect("/error")

        # Checks if the new passwords match
        if password != confirmation:
            flash("New and confirmation passwords must match")
            return redirect("/error")

        # This ensures that the password meets the required criteria
        if password:
            error_message = "Password format incorrect, must have at least one uppercase, one lowercase and numbers with a minimal length of 4 characters."
            if not any(x.isupper() for x in password):
                flash(error_message)
                return render_template("error.html")
            elif not any(x.islower() for x in password):
                flash(error_message)
                return render_template("error.html")
            elif not any(x.isdigit() for x in password):
                flash(error_message)
                return render_template("error.html")
            elif len(password) < 4:
                flash(error_message)
                return render_template("error.html")

        user = Users.query.filter_by(username=username, email=email).first()

        if not user:
            flash("User not registered. Check if the data was correct.")
            return redirect("/error")

        else:
            # This creates the token
            random = random_generator()
            validator = {"token" : random, "id" : user.id, "password" : generate_password_hash(password)}
            token = s.dumps(validator, salt="forgot-password")
            user.token = random
            db.session.commit()

            # This creates and send the email with the token
            msg = Message("Confirm your changes in your account", sender="MyOnlineAgendaCS50@gmail.com", recipients=[user.email])
            confirmation_link = url_for("reset_password", token=token, _external=True)
            msg.body = "Your validation link is <a href={}>here</a>.\nPlease be sure to use within the next 15 minutes as it will expire and you will need to register again.".format(confirmation_link)
            mail.send(msg)

        return redirect("/login")


# This uses the token sent via the verification email in order to verify the user request to change the password when forgetting it
@app.route("/reset_password/<token>", methods=["GET"])
def reset_password(token):
    if not token:
        flash("Missing token")
        return redirect("/error")
    else:
        try:
            validator = s.loads(token, salt="forgot-password", max_age=900)
            user = Users.query.filter_by(id=validator.get("id")).first()

            # This resets the user token in order to make the validation link only usable once during its lifetime
            if user.token:
                if user.token == validator.get("token"):
                    user.token = None
                    user.password = validator.get("password")
                    db.session.commit()
                    return redirect("/login")
                else:
                    flash("Tokens don't match. Generate a new validation link.")
                    return redirect("/error")
            else:
                flash("You already used this validation link. Make another one.")
                return redirect("/error")
        except SignatureExpired:
            flash("Your link expired. You must use it within 15 minutes after registering.")
            return redirect("/error")
        except BadTimeSignature:
            flash("Your validation link is wrong.")
            return redirect("/error")


# This removes a daily task from the database
@app.route("/removedailytask=<id>")
@login_required
def remove_daily_task(id):
    task = DailyTasks.query.filter_by(owner_id=current_user.get_id(), id=id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
        return redirect("/")
    else:
        flash("No task have been found")
        return redirect("/error")


# This removes a specific task from the database
@app.route("/removespecifictask=<id>")
@login_required
def remove_specific_task(id):
    task = SpecificTasks.query.filter_by(owner_id=current_user.get_id(), id=id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
        return redirect("/")
    else:
        flash("No task have been found")
        return redirect("/error")


# Handles errors
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    flash(e.code)
    flash(e.name)
    return redirect("/error")

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# Runs the app
if __name__ == "__main__":
    app.run(debug=True)