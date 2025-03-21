
import hashlib
import psycopg2
import tomllib
import string
import os
import random
import winreg
from tabulate import tabulate

class Policy:
    def check_policy(self, password):
        return all(password[i] != password[i + 1] for i in range(len(password) - 1))

class DBClass:
    def __init__(self, dbname, user, password, host, port):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port

    def request(self, command, args=None):
        try:
            with psycopg2.connect(database=self.dbname, user=self.user, password=self.password, port=self.port, host=self.host) as db:
                with db.cursor() as session:
                    session.execute(command, args or [])
                    return session.fetchall() if command.strip().lower().startswith('select') else None
        except psycopg2.Error as e:
            return e

    def create_init_table_if_exists(self):
        self.request('''CREATE TABLE IF NOT EXISTS users (
                                username varchar(255) PRIMARY KEY,
                                passw varchar(255),
                                is_blocked boolean NOT NULL DEFAULT 'No',
                                set_pass_policy boolean NOT NULL DEFAULT 'No');''')

class Auth:
    def __init__(self, db):
        self.db = db

    def identify(self, username):
        return bool(self.db.request("SELECT 1 FROM users WHERE username=%s;", (username,)))

    def is_blocked(self, username):
        result = self.db.request("SELECT is_blocked FROM users WHERE username=%s;", (username,))
        return result and result[0][0]

    def authenticate(self, username, password):
        result = self.db.request("SELECT passw FROM users WHERE username=%s;", (username,))
        return result and result[0][0] == password

class User:
    def __init__(self, username, password, db:DBClass):
        self.username = username
        self.password = password
        self.db = db

    def change_password(self):
        if input("Enter old password:") != self.password:
            print("Incorrect password!")
            return
        new_password = input("Enter new password:")
        is_pass_policy = self.db.request("SELECT set_pass_policy FROM users WHERE username=%s;", (self.username,))
        if is_pass_policy[0][0]:
            pass_pol_obj = Policy()
        if new_password == self.password:
            print("New password cannot be the same!")
            return

        if is_pass_policy and not pass_pol_obj.check_policy(new_password):
            print("Password does not comply with password policy")
            return

        ack_passwd = input("Enter new password again:")
        if ack_passwd!=new_password:
            print("Entered password does not match with new password!")
            return

        self.db.request("UPDATE users SET passw=%s WHERE username=%s;", (new_password, self.username))
        self.password = new_password
        print("Password changed successfully!")

    def help(self):
        print("Commands: help, exit, passwd, info")

    def info(self):
        print("Author: student of group FB-21 Shabanov Kyrylo \n Individual task: 16. No consecutive identical characters.")

    def close(self):
        exit()

class Admin(User):
    def list_users(self):
        print(tabulate(self.db.request("SELECT username, is_blocked, set_pass_policy FROM users;"), headers=['Username', 'Blocked','PassPolicy']))

    def add_user(self):
        username = input("Enter username: ")
        if not Auth(self.db).identify(username):
            self.db.request("INSERT INTO users(username, passw) VALUES(%s, '');", (username,))
            print("User added successfully!")
        else:
            print("Username already taken!")

    def block_user(self):
        username = input("Enter username: ")
        if username=='admin':
            print("Admin cannot block himself!")
            return
        request = self.db.request("SELECT is_blocked FROM users WHERE username=%s;", (username,))
        if request and request[0][0]==False:
            self.db.request("UPDATE users SET is_blocked = TRUE WHERE username=%s;", (username,))
            print("User blocked!")
        elif request and request[0][0]==True:
            self.db.request("UPDATE users SET is_blocked = FALSE WHERE username=%s;", (username,))
            print("User unblocked!")
        else:
            print("Unknown username!")

    def set_policy(self):
        username = input("Enter username: ")
        request = self.db.request("SELECT set_pass_policy FROM users WHERE username=%s;", (username,))
        if request and request[0][0]==False:
            self.db.request("UPDATE users SET set_pass_policy = TRUE WHERE username=%s;", (username,))
            print("Password policy set!")
        elif request and request[0][0]==True:
            self.db.request("UPDATE users SET set_pass_policy = FALSE WHERE username=%s;", (username,))
            print(f"Password policy removed from {username} account!")
        else:
            print("Unknown username!")

    def help(self):
        print("Commands: help, exit, passwd, block, adduser, list_u, set_policy, info")

def main(db):
    num_att = 2
    auth = Auth(db)
    try:
        while num_att>-1:
            username = input("Enter username: ")
            password = input("Enter password: ")
            if auth.authenticate(username, password) and not auth.is_blocked(username):
                break
            print("Invalid credentials!")
            num_att-=1

        if num_att<0:
            return

        #Authorization
        user = Admin(username, password, db) if username == 'admin' else User(username, password, db)
        print("Welcome!")
        user.help()
        while True:
            cmd = input(f"{user.username}> ").strip().lower()
            if cmd == "passwd": user.change_password()
            elif cmd == "help": user.help()
            elif cmd == "info":user.info()
            elif cmd == "exit": user.close()
            elif isinstance(user, Admin) and cmd == "list_u": user.list_users()
            elif isinstance(user, Admin) and cmd == "adduser": user.add_user()
            elif isinstance(user, Admin) and cmd == "block": user.block_user()
            elif isinstance(user, Admin) and cmd == "set_policy": user.set_policy()
            else: print("Unknown command!")

    except KeyboardInterrupt:
        print("Exiting from interrupt!")
        exit(0)

if __name__ == '__main__':
    with open('conf.toml', 'rb') as tf:
        data = tomllib.load(tf)
    db_info = data['database']
    db = DBClass(db_info['name'], db_info['user'], db_info['password'], db_info['host'], db_info['port'])
    db.create_init_table_if_exists()
    main(db)