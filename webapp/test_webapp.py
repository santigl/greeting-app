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


import os
import app
import unittest
import tempfile
import sqlite3

class AppTestCase(unittest.TestCase):

    def setUp(self):
        app.app.testing = True
        # We create a brand-new DB with the `users`table defined:
        self.db_file = self.createEmptyDB()
        app.app.config['USERS_DATABASE'] = self.db_file

        self.app_client = app.app.test_client()

    def tearDown(self):
        os.unlink(self.db_file)

    def createEmptyDB(self):
        (_, db_file) = tempfile.mkstemp(suffix='.db')
        conn = sqlite3.connect(db_file)

        # Loading schema from file...
        with open('users.sql') as f:
            db_schema = f.read()

        cursor = conn.cursor()
        cursor.executescript(db_schema)
        return db_file


    def test_index_loads(self):
        rv = self.app_client.get('/')
        assert b'Welcome to the Greeting App.' in rv.data


    def test_registration(self):
        r = self.register('username1', 'password123')
        assert b'Logged in as' in r.data and b'username1' in r.data


    def test_login(self):
        self.register('username2', 'password1234')
        self.logout()
        r = self.login('username2', 'password1234')
        assert b'Logged in as' in r.data and b'username2' in r.data


    def test_password_check(self):
        r = self.register('username1', 'password1234')
        r = self.login('username1', 'password1235')
        assert  b'Username and/or password not valid.' in r.data


    def test_mismatched_passwords(self):
        r = self.register('username1', 'mypassword', 'mypassworf')
        assert b'The passwords do not match' in r.data


    def test_greeting(self):
        self.register('luckyuser', 'luckypassword')
        r = self.app_client.get('/greeting')
        assert b'Stay hungry and foolish, luckyuser.' in r.data


    def test_not_logged_in(self):
        r = self.app_client.get('/greeting')
        assert '/index' in r.headers.get('Location', type=str)


    def login(self, username, password):
        return self.app_client.post('/login',
                                    data=dict(username=username,
                                              password=password),
                                    follow_redirects=True)


    def register(self, username, password, password_confirmation=None):
        if not password_confirmation:
            password_confirmation = password

        data = {'username': username, 'password': password,
                'passwordConfirmation': password_confirmation}

        return self.app_client.post('/register', data=data,
                                    follow_redirects=True)


    def logout(self):
        return self.app_client.get('/logout', follow_redirects=True)



if __name__ == '__main__':
    unittest.main()
