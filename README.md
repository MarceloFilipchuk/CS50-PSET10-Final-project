# CS50-PSET10-Final-project

This app allows you to register using your email. It will send a validation link to your adress (be sure to check your spam folder), which you can only use once and that will
expire after 15 minutes. Once validated, you will be able to log in using your username and password. Inside the index you will find a calendar,
a weather section and two task lists, one for daily tasks (the kind that are done every day, i.e. taking some medication, go to the gym, etc) and
another one for date specific tasks, which will be shown according to the date selected on the calendar. It also allows the user to change its username,
email or password. In case you forget your password, you can reset it by using the "Forgot password" inside the log in screen. In order to apply the changes
you will need to open a verification link that will be sent to your email address (again, be sure to check your spam folder).
It was designed as a small and practic agenda for quick use.

Usage:

> pip install -r requirements.txt

> export / set FLASK_APP=application.py

> export / set MAIL_PASSWORD= Im the only one who knows this one

> export / set API_KEY= You have to get your own from the OWM web by registering

> run flask
