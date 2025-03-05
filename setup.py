import os
import winreg
from hashlib import sha512
from ctypes import windll

def get_info():
    current_user = os.getlogin()
    computer_name = os.environ['COMPUTERNAME']
    win_path = os.environ['SystemRoot']
    sys_file_path = win_path+'\\System32'

    #GetTypeKeyboardAndSubtype
    type_keyboard = str(windll.user32.GetKeyboardType(0))
    subtype = str(windll.user32.GetKeyboardType(1))
    screen_size = str(windll.user32.GetSystemMetrics(0)) +',' + str(windll.user32.GetSystemMetrics(1))
    set_disks = ''.join(i for i in os.listdrives())

    return f"{current_user};{computer_name};{win_path};{sys_file_path};{type_keyboard};{subtype};{screen_size};{set_disks};"

def genhash(data:str):
    return sha512(bytes(data, encoding='utf-8')).hexdigest()

def write_to_reg(signature:str):
    key = winreg.HKEY_CURRENT_USER
    sub_key = 'SOFTWARE\\Shabanov'
    hkey = winreg.CreateKey(key,sub_key)
    winreg.SetValueEx(hkey,'Signature',0, winreg.REG_SZ, signature)
    winreg.CloseKey(hkey)

def download(from_dir,to):
    try:
        with open(from_dir, 'rb') as fl:
            data = fl.read()
        with open(to,'wb') as fl:
            fl.write(data)

    except FileNotFoundError:
        return -1

    return 0

def main():
    default_path = os.path.join(os.environ['USERPROFILE'],'Documents')
    files = ['app.py','crypto.py']
    conf_files = ['conf.toml']
    root_directory = 'Accountman'
    conf_directory = 'conf'
    try:
        print("Встановлення залежностей...")
        os.system("pip install -r requirements.txt")

        path = input(f"Введіть місцерозташування програми({default_path}):")
        if not path:
            path = default_path

        root_fin_dir = os.path.join(path, root_directory)
        conf_fin_dir = os.path.join(root_fin_dir, conf_directory)

        print(f"Створення {conf_fin_dir}")
        if os.path.exists(conf_fin_dir):
            print("Каталог вже встановлений")
        else:
            os.makedirs(conf_fin_dir)

        for i in files:
            path_file = os.path.join(root_fin_dir,i)
            if download(i,path_file):
                print("Не можемо знайти файл ", i)
                print("Скасування... ")
                return -1

        for i in conf_files:
            path_file = os.path.join(conf_fin_dir,i)
            if download(i, path_file):
                print("Не можемо знайти файл ", i)
                print("Скасування... ")
                return -1

        print("Створення записів до реєстру...")
        label_vol = f"{path.split('\\')[0]};"
        write_to_reg(genhash(get_info()+label_vol))

        print("Залежності встановлено!")
        print("Встановлення закінчено!")
        return 0
    except KeyboardInterrupt:
        print("Вихід з програми!")

if __name__=='__main__':
    main()