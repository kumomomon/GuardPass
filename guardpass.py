import sqlite3
import argparse
import os
import getpass
import base64
import secrets
from zxcvbn import zxcvbn
from prettytable import PrettyTable
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

GREEN, YELLOW, RED, RESET = "\033[92m" + "[+] ", "\033[93m" + "[!] ", "\033[91m" + "[-] ", "\033[0m"
table = PrettyTable()
table.align = "l"

def get_masterpw():
    check_masterpw = True
    while check_masterpw:
        master_password = getpass.getpass("Enter Master Password: ")
        password_validator, warning, suggestions = validate_password(master_password, None, None)
        if master_password != "":
            check_masterpw = False
        elif password_validator:
            print("Password is too weak. Please choose a stronger password.")
            print(RED + "Warning: {}".format(warning) + RESET)
            print(RED + "Suggestion: {}".format(suggestions) + RESET)
        else:
            print(RED + "No password detected, please try again." + RESET)
    return master_password

def get_key(master_password, password, salt, mode):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    f = Fernet(key)
    if mode == "encrypt":
        encrypted_pasword = f.encrypt(password.encode())
        return encrypted_pasword.decode("utf-8")
    elif mode == "decrypt":
        decrypted_pasword = f.decrypt(password.encode())
        return decrypted_pasword.decode("utf-8")

def validate_password(password, username=None, domain=None):
    if username == None and domain == None:
        results = zxcvbn(password)
    else:
        results = zxcvbn(password, user_inputs=[username, domain])
    if results["score"] >= 3:
        return False, None, None
    else:
        return True, results["feedback"]["warning"], results["feedback"]["suggestions"][0]

def main_database(options, username=None, domain=None):
    try:
        database_status, database_check = check_database()
        print(database_status)
        con = sqlite3.connect("database.db")
        cur = con.cursor()
        if database_check == False:
            cur.execute("CREATE TABLE password_list(username, domain, password, salt)")
        if options == "insert":
            insert_database(cur, username, domain)
        elif options == "delete":
            delete_database(cur, username, domain)
        con.commit()
        display_database(cur, username, domain)
        con.close()
    except KeyboardInterrupt: 
        print("\n" + RED + "Ctrl + C detected." + RESET)
    except InvalidToken:
        print("\n" + RED + "Invalid Master Password." + RESET)
    except Exception as e: 
        print("\n" + RED + "An expected error occured: {}".format(e) + RESET)

def check_database():
    database_exist = "database.db"
    if not os.path.exists(database_exist):
        return GREEN + "Creating Database!" + RESET, False
    else:
        return GREEN + "Database found!" + RESET, True

def display_database(cur, username, domain):
    table.clear()
    if username == None and domain == None:
        cur.execute("SELECT * FROM password_list ORDER BY domain")
    elif username == None:
        data = [domain]
        cur.execute("SELECT * FROM password_list WHERE domain=?", data)
    elif domain == None:
        data = [username]
        cur.execute("SELECT * FROM password_list WHERE username=?", data)
    else:
        data = [username, domain]
        cur.execute("SELECT * FROM password_list WHERE username=? AND domain=?", data)
    rows = cur.fetchall()
    if not rows:
        print(RED + "No credentials found!" + RESET)
    else:
        for name, domain, password, salt in rows:
            master_password = get_masterpw()
            decrypt_password = get_key(master_password, password, salt, "decrypt")
            table.field_names = ["Name", "Domain", "Password"]
            table.add_row([name, domain, decrypt_password])
        print(table)

def insert_database(cur, username, domain):
    if username == None:
        username = input("Enter Username: ")
    if domain == None:
        domain = input("Enter Domain: ")
    data = [username, domain]
    cur.execute("SELECT * FROM password_list WHERE username=? AND domain=?", data)
    rows = cur.fetchall()
    if not rows:
        password_counter = 0
        while password_counter < 3:
            password = getpass.getpass("Enter Password: ")
            cfm_password = getpass.getpass("Confirm Password: ")
            password_validator, warning, suggestions = validate_password(password, username, domain)
            if password != cfm_password:
                print("Password mismatched. Please try again")
                password_counter += 1
            elif password_validator:
                print("Password is too weak. Please choose a stronger password.")
                print(RED + "Warning: {}".format(warning) + RESET)
                print(RED + "Suggestion: {}".format(suggestions) + RESET)
            else:
                salt = secrets.token_hex(32)
                master_password = get_masterpw()
                validate_masterpw = validate_password
                encrypted_pasword = get_key(master_password, password, salt, "encrypt")
                data = [username, domain, encrypted_pasword, salt]
                cur.execute("INSERT INTO password_list VALUES(?, ?, ?, ?)", data)
                break    
    else:
        update_check = input("Credentials already exists in database. Do you want to update the password? [Y/n] ")
        if update_check.upper() == "Y" or update_check == "":
            update_database(cur, username, domain)

def update_database(cur, username, domain):
    if username == None:
        username = input("Enter Username: ")
    if domain == None:
        domain = input("Enter Domain: ")
    data = [username, domain]
    cur.execute("SELECT * FROM password_list WHERE username=? AND domain=?", data)
    rows = cur.fetchall()
    if not rows:
        print(RED + "Username {} with domain {} is not in the database.".format(username, domain) + RESET)
    else:
        password_counter = 0
        while password_counter < 3:
            password = getpass.getpass("Enter Password: ")
            cfm_password = getpass.getpass("Confirm Password: ")
            password_validator, warning, suggestions = validate_password(password, username, domain)
            if password != cfm_password:
                print("Password mismatched. Please try again")
                password_counter += 1
            elif password_validator:
                print("Password is too weak. Please choose a stronger password.")
                print(RED + "Warning: {}".format(warning) + RESET)
                print(RED + "Suggestion: {}".format(suggestions) + RESET)
            else:
                data = [username, domain, password]
                cur.execute("UPDATE password_list SET password=? WHERE username=? AND domain=?", data)
                break

def delete_database(cur, username, domain):
    if username == None:
        username = input("Enter username: ")
    if domain == None:
        domain = input("Enter domain: ")
    data = [username, domain]
    delete_password = input(RED + "Deleting {} from {}. Confirm deletion? [Y/n] ".format(username, domain) + RESET)
    if delete_password.upper() == "Y" or delete_password == "":
        cur.execute("DELETE FROM password_list WHERE username=? AND domain=?", data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Local Password Manager to Guard your Password [Default: Current Directory]', epilog='Just for fun only!')
    parser.add_argument("-p", "--path", help="Specify path to read/store password database", dest="path")
    parser.add_argument("-u", "--username", help="Specify username", dest="username")
    parser.add_argument("-d", "--domain", help="Specify domain", dest="domain")
    parser.add_argument("-o", "--options", choices=["insert", "delete", "update"], help="Options: open, move, rename, delete", dest="options")
    args = parser.parse_args()
    main_database(args.options, args.username, args.domain)
