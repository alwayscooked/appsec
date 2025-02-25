import psycopg2
import tomllib
from tabulate import tabulate
class SecApp:
    def secinput(self, text):
        special_chars = "/?*'-"
        while True:
            val = input(text)
            if not any(c in special_chars for c in val):
                break

            print("Без спеціальних символів!")
        return val

    def check_policy(self, password):
        for i in range(len(password) - 1):
            if password[i] == password[i + 1]:
                return False
        return True

class DBClass:
    def __init__(self, dbname:str, user:str, password:str, host:str, port:str):
        with psycopg2.connect(database=dbname, user=user, password=password, port=port,host=host): pass
        self.dbname = dbname
        self.user = user
        self.passw = password
        self.host = host
        self.port = port

    def request(self,command:str):
        try:
            with psycopg2.connect(database=self.dbname, user=self.user, password=self.passw, port=self.port, host=self.host) as db:
                with db.cursor() as session:
                    session.execute(command)
                    if command.split()[0].lower()=='select':
                        return session.fetchall()
                    return 0
        except psycopg2.Error as e:
            return e

class Auth:
    def __init__(self, db:DBClass):
        self.db = db

    def identify(self, username):
        if self.db.request(f"SELECT * FROM users WHERE username='{username}';"):
            return True
        return False

    def isblock(self, username):
        is_blocked = self.db.request(f"SELECT is_blocked FROM users WHERE username='{username}';")
        if is_blocked[0][0]:
            return True
        return False

    def authentication(self, username, passw):
        dbp = self.db.request(f"SELECT passw FROM users WHERE username='{username}';")
        if passw==dbp[0][0]:
            return True
        return False

class User:
    def __init__(self, username ,password ,db:DBClass):
        self.username = username
        self.password = password
        self.db = db

    def passwd(self):
        while input("Введіть старий пароль:")!=self.password:
            print("Пароль не співпадає!")

        policy = self.db.request(f"SELECT set_pass_policy FROM users WHERE username='{self.username}';")[0][0]
        if policy:
            sec_p = SecApp()
        try:
            while True:
                new_password = input("Введіть новий пароль:")
                if (not policy or sec_p.check_policy(new_password)) and (new_password != self.password):
                    break
                if policy and not sec_p.check_policy(new_password):
                    print("Наявні підряд розташовані однакові символи!")
                    continue
                print("Новий пароль не може співпадати зі старим!")

        except (KeyboardInterrupt, EOFError):
            print("Вихід у головне меню!")
            return -1

        try:
            while input("Введіть пароль ще раз для підтвердженя: ")!=new_password:
                print("Пароль не співпадає з введеним, спробуйте ще!")

        except (KeyboardInterrupt, EOFError):
            print("Скасування зміни пароля!")
            return -1

        req = self.db.request(f"UPDATE users SET passw='{new_password}' WHERE username='{self.username}';")
        if not req:
            self.password = new_password
            print("Пароль успішно змінено!")
            return 0
        print(req)
        return  -1

    def help(self):
        list_comm = ['help - довідка по командам',
                     'exit - вихід з програми',
                     'passwd - зміна паролю',
                     'block - заблокувати акаунт',
                     'adduser - додати користувача',
                     'set_policy - встановити політику паролів',
                     'listu - список користувачів',
                     'info - про програму']
        for i in list_comm:
            print(i)

    def info(self):
        infor = '''Автор: студент ФБ-21 Шабанов Кирило
Індивідуальне завдання: 16. Відсутність підряд розташованих однакових символів.'''
        print(infor)

    def close(self):
        raise KeyboardInterrupt

class Admin(User):
    def listu(self):
        return self.db.request(f"SELECT username,is_blocked,set_pass_policy FROM users;")

    def adduser(self):
        auth = Auth(self.db)
        try:
            while True:
                username = input("Введіть ім'я користувача: ")
                if not auth.identify(username):
                    self.db.request(f"INSERT INTO users(username, passw) VALUES('{username}','');")
                    print("Користувач доданий успішно!")
                    break
                print("Це ім'я користувача вже зайняте!")

        except (KeyboardInterrupt, EOFError):
            print("Вихід у головне меню!")
            return -1

    def block(self):
        iden = Auth(self.db)
        try:
            while True:
                username = input("Введіть ім'я користувача: ")
                if iden.identify(username):
                    break
                print("Такого користувача не існує! Спробуйте ще!")

        except (KeyboardInterrupt, EOFError):
            print("Вихід у головне меню!")
            return -1

        if username == 'admin':
            print("Адмін не може сам себе блокнути!")
            return -2

        try:
            while True:
                state = input("Введіть стан (t(rue)/f(alse): ")
                match state:
                    case 't' | 'f':
                        self.db.request(f"UPDATE users SET is_blocked='{state}' WHERE username='{username}';")
                        return 0
                    case _:
                        print("Помилка при введені стану! Спробуйте ще!")
        except (KeyboardInterrupt, EOFError):
            print("Скасування операції!")
            return -2

    def policy(self):
        iden = Auth(self.db)
        try:
            while True:
                username = input("Введіть ім'я користувача: ")
                if iden.identify(username):
                    break
                print("Такого користувача не існує! Спробуйте ще!")

        except (KeyboardInterrupt, EOFError):
            print("Вихід у головне меню!")
            return -1
        try:
            while True:
                state = input("Введіть стан (t(rue)/f(alse): ")
                match state:
                    case 't' | 'f':
                        self.db.request(f"UPDATE users SET set_pass_policy='{state}' WHERE username='{username}';")
                        return 0
                    case _:
                        print("Помилка при введені стану! Спробуйте ще!")
        except (KeyboardInterrupt, EOFError):
            print("Скасування операції!")
            return -2


def main(db_session:DBClass):
    num_attempts = 2
    auth = Auth(db_session)
    try:
        while True:
            username = input("Введіть ім'я користувача: ")
            if auth.isblock(username):
                print('Акаунт заблокований!')
                raise KeyboardInterrupt

            passw = input("Введіть пароль: ")
            if auth.identify(username) and auth.authentication(username, passw):
                break
            print("Ім'я користувача, або пароль не є правильними!")
            num_attempts-=1

            if num_attempts<0:
                print('Кількість спроб вичерпано!')
                exit(-1)

        if username=='admin':
            user = Admin(username, passw, db_session)
        else:
            user = User(username, passw, db_session)

        print('Вітаємо!')
        user.help()
        while True:

            comm = (input(f"{user.username}> "))

            match comm.lower().strip():
                case 'passwd': user.passwd()

                case 'help': user.help()

                case 'info':user.info()

                case 'exit': user.close()

                case 'adduser' if isinstance(user, Admin): user.adduser()

                case 'block' if isinstance(user, Admin): user.block()

                case 'set_policy' if isinstance(user, Admin):user.policy()

                case 'listu' if isinstance(user, Admin):
                    print(tabulate(user.listu(),headers=['username', 'is_blocked', 'is_password_policy']))

                case 'adduser' | 'block' | 'set_policy' | 'listu' if not isinstance(user, Admin):
                    print("Права на виконання даної команди відсутні!")

                case _: print('Команду не знайдено!')

    except KeyboardInterrupt:
        print("Вихід з програми!")

if __name__=='__main__':
    with open('conf.toml', 'rb') as tf:
        data = tomllib.load(tf)

    dt_table = data['database']
    db_session = DBClass(dt_table['name'],dt_table['user'],dt_table['password'],dt_table['host'],dt_table['port'])
    main(db_session)