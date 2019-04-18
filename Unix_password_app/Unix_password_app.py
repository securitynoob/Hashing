#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import hashlib
import uuid
import json
from pathlib import Path

def load_new_password(user_name, password, password_file):
    try:
        salt = uuid.uuid4().hex
        check = password_file[user_name]['SALT']
        print("Username already exists!!")
    except KeyError:
        hash_code = hashlib.sha256((password+salt).encode('utf-8'))
        ret = {user_name: {'SALT': salt,
                           'HASH_CODE': hash_code.hexdigest()
                          }
              }
        return ret
    
def verify_password(user_name, password, password_file):
    try:
        salt = password_file[user_name]['SALT']
        checker = hashlib.sha256((password+salt).encode('utf-8'))
        return password_file[user_name]['HASH_CODE'] == checker.hexdigest()
    except KeyError:
        print("Username doesn't exist!!")

def change_password(username, password, new_password, password_file):
    try:
        salt = password_file[username]['SALT']
        checker = hashlib.sha256((password+salt).encode('utf-8'))
        if password_file[username]['HASH_CODE']  == checker.hexdigest() :
            hash_code = hashlib.sha256((new_password+salt).encode('utf-8'))
            ret = {username: {'SALT': salt,
                            'HASH_CODE': hash_code.hexdigest()
                          }
                  }
            return ret
        else:
            print("Wrong Password!")
    except KeyError:
        print("Username doesn't exist!!")
    
#--------------UNIX PASSWORD SYSTEM APPLICATION--------------#
User_type = input("New User? If Yes type Y. If not type N:")
password_list = {}
file = Path("password_list.txt")

if file.exists():
    file = open(file,"r")
else:
    file = open(file,"w+")

if file.read() > '0':
    with open("password_list.txt","r") as line:
        password_list.update(json.load(line))
if User_type == 'Y':
    print("Please enter your username and password to Sign Up!!")
    username = input("USERNAME:")
    password = input("PASSWORD:")
    password_hash = load_new_password(username,password,password_list)
    try:
        password_list.update(password_hash)
        with open("password_list.txt","r+") as line:
            json.dump(password_list, line)
    except:
        print("Sign Up Failed!!")
        
    
elif User_type =='N':
    print("Please enter your username and password to Sign In!!")
    username = input("USERNAME:")
    password = input("PASSWORD:")
    login = verify_password(username,password,password_list)
    if login:
        print("Sign In Success!!")
        
    else:
        print("Sign In Failed!")
else:
    print("Please follow the instructions!!")
    
Change_password = input("Change Password? If Yes type Y. If not type N:")
if Change_password == 'Y':
    username = input("USERNAME:")
    password = input("OLD PASSWORD:")
    new_password = input("NEW PASSWORD:")
    password_hash = change_password(username,password,new_password,password_list)
    try:
        password_list.update(password_hash)
        with open("password_list.txt","w") as line:
            json.dump(password_list, line)
        print("Your password has been changed!!")
    except TypeError:
        print("Password change failed!!")
        
elif Change_password == 'N':
    print("Okay!!")
else:
    print("Please follow the instructions!!")


# In[ ]:




