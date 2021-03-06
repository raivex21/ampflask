from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
import time
import re
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import MySQLdb



app = Flask(__name__)
app.debug=True

#config mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'r41v3x21'
app.config['MYSQL_DB'] = 'amp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#init mysql

mysql = MySQL(app)



@app.route('/')
def index():
    return render_template('home.html', active='index')

@app.route('/about')
def about():
    return render_template('about.html', active='about')

@app.route('/members')
def members():
    return render_template('members.html', active='members')

@app.route('/articles')
def articles():
    return render_template('articles.html', active='articles')

#check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, Please login", 'danger')
            return redirect(url_for('login'))
    return wrap


#dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


class RegisterForm(Form):
    username = StringField('', [validators.Length(min=1, max=50)], render_kw={"placeholder": "Username"})
    firstname = StringField('', [validators.Length(min=1, max=50)], render_kw={"placeholder": "First Name"})
    lastname = StringField('', [validators.Length(min=1, max=50)], render_kw={"placeholder": "Last Name"})
    email = StringField('', [validators.Length(min=1, max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField('', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ], render_kw={"placeholder": "Password"})
    confirm = PasswordField('', render_kw={"placeholder": "Confirm Password"})

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #create cursor
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users(username, password, email, firstname, lastname) VALUES (%s, %s, %s, %s, %s)", (username, password, email, firstname, lastname))
        except mysql.connection.IntegrityError as err:
            error = 'Username already taken'
            flash('Username already taken', 'warning')
            return redirect(url_for('register'))
            cur.close()
        #commit to DB
        mysql.connection.commit()

        #close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)
        





#user login
@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        #get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # create cursor
        cur = mysql.connection.cursor()

        #get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            #get stored hash
            data = cur.fetchone()
            password = data['password']

            #compare password
            if sha256_crypt.verify(password_candidate, password):
                #passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)

            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')





@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key='secret123'
    app.run()
