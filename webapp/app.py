# BSD 2-Clause License
#
# Copyright (c) 2018, Santiago Gil
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import base64
import time
import sqlite3
import requests

from flask import Flask, render_template, request, session, redirect, url_for
from flask_bcrypt import generate_password_hash, check_password_hash

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding



app = Flask(__name__)
if not app.testing:
    app.config.from_pyfile('app.cfg')


# TODO: Check out unit testing for Flask

@app.route('/')
@app.route('/index')
def index():
    """Render the index page."""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Process the registration data sent, or display the registration
    form if no data is received.
    """
    register_page_template = 'register.html'

    if request.method == 'GET':
        if 'username' in session:
            # If the user is logged in and got to the register form
            # by mistake, we redirect to the index.
            return redirect(url_for('index'))

        return render_template(register_page_template)


    # (This is a POST request, so we received data.)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    password_confirmation = request.form.get('passwordConfirmation', '')

    if not is_username_valid(username):
        return render_template(register_page_template,
                               error_message='The chosen username is not valid.')

    if password != password_confirmation:
        return render_template(register_page_template,
                               username=username,
                               error_message='The passwords do not match.')

    if is_user_registered(username):
        return render_template(register_page_template,
                               error_message='That username is taken.')

    # Everything looks good, we add the new user to the database:
    register_username(username, password)

    # Log the user in and redirect to the index:
    session['username'] = username
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Show the login form if no data is received.
    Otherwise process the login request.
    """
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if are_credentials_valid(username, password):
        session['username'] = username
        return redirect(url_for('index'))

    return render_template('login.html',
                           error_message='Username and/or password not valid.')


@app.route('/logout')
def logout():
    """Remove the username from the session dictionary."""
    del session['username']
    return redirect(url_for('index'))


@app.route('/greeting')
def show_user_greeting():
    """Display the logged in user's greeting."""
    greeting_page_template = 'greeting.html'

    # User has to be logged in.
    if 'username' not in session:
        return redirect(url_for('index'))

    token = generate_token(session['username'])

    # Sending the request to the backend:
    try:
        url = '{}?token={}'.format(app.config['BACKEND_ENDPOINT'],
                                    token)
        reply = requests.get(url)

        if reply.status_code == 200:
            return render_template(greeting_page_template,
                                   greeting_message=reply.text)

        return render_template(greeting_page_template,
                               error_message=reply.text)

    except:
        return render_template(greeting_page_template,
                               error_message="Could not connect to the backend.")


### Database Functions ###
def database_connection():
    """Return the database connection handler."""
    return sqlite3.connect(app.config['USERS_DATABASE'])

def is_username_valid(username):
    """Returns whether the username consists of legal characters
    and is of a reasonable length.
    """
    return username.isalnum() and (len(username) <= 30)


def is_user_registered(username):
    """Returns whether the username is already in the DB."""
    sqlite_connection = database_connection()
    cursor = sqlite_connection.cursor()
    cursor.execute('SELECT count(*) FROM users WHERE username=?', (username,))
    result = cursor.fetchone()[0]

    return result > 0


def register_username(username, password):
    """Inserts the username and hashed password into the database."""
    sqlite_connection = database_connection()
    cursor = sqlite_connection.cursor()

    password_hash = generate_password_hash(password, 13)

    cursor.execute("""INSERT INTO users (username, password)
                      VALUES(?,?)""", (username, password_hash))
    sqlite_connection.commit()
    sqlite_connection.close()


def are_credentials_valid(username, password):
    """Returns whether a given username is stored in the
     database and, if it is, if the passwords match.
    """
    sqlite_connection = database_connection()
    cursor = sqlite_connection.cursor()

    cursor.execute('SELECT password FROM users WHERE username=?', (username,))

    match = cursor.fetchone()

    if not match:
        return False

    stored_hash = match[0]
    return check_password_hash(stored_hash, password)


### Token/Signing Functions ###
def generate_token(username):
    """Generates a token with the format (username:timestamp:signature).
    The signature is encoded in url-safe base64.
    """
    # Loading our private key:
    with open(app.config['PRIVATE_KEY_PATH'], 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(),
                                                         password=None,
                                                         backend=default_backend())

    # Our message contains the username and the current timestamp,
    # separated by a colon.
    timestamp = int(time.time())
    data = '{}:{}'.format(username, timestamp)

    # We sign it...
    signature = sign_message(private_key, data)
    # and get the signature represented as a base64 string:
    signature_base64 = str(base64.urlsafe_b64encode(signature),
                           encoding='utf-8')

    # The token is "username:timestamp:signature".
    token_data = '{}:{}'.format(data, signature_base64)

    return token_data


def sign_message(private_key, message):
    """Signs a string with an RSA private key."""

    # Convert the string to bytes:
    message_bytes = bytes(message, 'utf-8')

    padding_method = padding.PKCS1v15()
    hashing_function = hashes.SHA256()

    signature = private_key.sign(data=message_bytes,
                                 padding=padding_method,
                                 algorithm=hashing_function)

    return signature


if __name__ == '__main__':
    app.run(debug=True)
