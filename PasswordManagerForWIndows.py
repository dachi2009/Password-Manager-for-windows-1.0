import os
import secrets
import json
import hashlib
import string
import pathlib
import base64
import sys
from cryptography.fernet import Fernet
from colorama import Fore, Style, init
import getpass
import time
import cryptography
import platform
import concurrent.futures as ccf
init(autoreset=True)
fr = Fore
try:
    import ntsecuritycon as nc
    import win32security
except ImportError:
    print(fr.RED + f"[!] Cant find win32security library! (pywin32 isnt installed on system!)\nInstallable with --> 1) Open command prompt as administrator",
                      '\n' + fr.RED + "2)'python -m pip install --upgrade pywin32'",
                      '\n' + fr.RED + "3) Verify with: python -c \"import win32api; print('pywin32 installed successfully')\"", Style.RESET_ALL)
print(fr.RED + "[!] be very careful if you decide to edit path variables as it may change some of ur files permissions in other directories so do it wisely and read whole code to stay safe!",Style.RESET_ALL)
user = getpass.getuser()
home = pathlib.Path.home() / ".pm_data" # <-- DO NOT EDIT THIS IF YOU DO THEN YOU WILL HAVE TO EDIT FEW LINES ALSO 
password_file = home / "passwords.json" # <-- EDIT THIS IF YOU EDIT home VARIABLE
def MakeSure():
    if not os.path.exists(home):
        print(fr.RED + f"[!] couldnt find passwords file in '{home}'\nCreating one...")
        print(Style.RESET_ALL)
        home.mkdir(parents=True, exist_ok=True)
        print(fr.CYAN + f"[+] Successfully created directory: {home}")
        print(Style.RESET_ALL)
        
    if not password_file.exists():
        with open(password_file, 'w') as a:
            json.dump({}, a, indent=4)
            print(fr.GREEN + f"[+] Successfully created {password_file}")
            print(Style.RESET_ALL)
    else:
        print(fr.RED + f"[!] File {password_file} already exists so can't create new one")
        print(Style.RESET_ALL)


MakeSure()

salt_bytes = 64
iters = 3_500_000
path_to_file = password_file # <-- EDIT THIS TO path_to_file = home IF YOU EDIT HOME VARIABLE
MainFile = path_to_file


class PasswordManager:
    def __init__(self):
        self.salt_for_sha256 = None
        self.Fe = None
        self.MasterPasswordSalt = None
        self.MainFile = MainFile
        self.whole_data = self.FileOpener()
        
    def FileOpener(self):
        
        try:
            with open(self.MainFile, 'r') as a:
                read_file = a.read()
                return json.loads(read_file) if read_file else {}
        
        except FileNotFoundError:
            print(fr.RED + f"[!] Couldnt find file path {self.MainFile} did you edit MakeSure() function or commented it out? seriously?! 💔\n[!] fine i will run it for you lil bro 💔🥀")
            print(Style.RESET_ALL)
            print(fr.RED + "[!] you have to re-run program again as it can cause infinite loop if this script edited not correctly")
            MakeSure()
            sys.exit()
        
        except PermissionError:
            print(fr.RED + f"[!] There's no way you edited MakeSure() function or file path and set it to other thats why it says permission error on my side 💔\n[!] attempting to create file...")
            print(Style.RESET_ALL)
            MakeSure()
            print(fr.RED + "[!] you have to re-run program again as it can cause infinite loop if this script edited not correctly")
            sys.exit()
        
        except json.decoder.JSONDecodeError:
            print(fr.RED + f"[!] uh oh json is curropted uff 🫨😣\n[!] attempting to create file")
            print(Style.RESET_ALL)
            MakeSure()
            print(fr.RED + "[!] you have to re-run program again as it can cause infinite loop if this script edited not correctly")
            sys.exit()
            
    def FileWriter(self):
        
        with open(self.MainFile, 'w') as a:
            json.dump(self.whole_data, a, indent=4)
        print(fr.GREEN + "[+] Successfully updated data")
    
    def MasterPassword(self):
    
        if "master_salt" in self.whole_data:
            self.MasterPasswordSalt = self.whole_data["master_salt"]
    
        if self.MasterPasswordSalt is None:
            print(fr.RED + "[!] Couldnt find master password so creating one...")
            print(Style.RESET_ALL)
            big_letts = string.ascii_uppercase
            small_letts = string.ascii_lowercase
            digits = string.digits
            symbols = r"!@#$%^&*()[]\/`~'.,"
            while True:
                has_upper = False
                has_lower = False
                has_digits = False
                has_symbols = False
                master_password = getpass.getpass(fr.YELLOW + "enter password: ")
                for char in master_password:
                    if char in big_letts:
                        has_upper = True
                    if char in small_letts:
                        has_lower = True
                    if char in digits:
                        has_digits = True
                    if char in symbols:
                        has_symbols = True
                if len(master_password) >= 8 and has_upper and has_lower and has_digits and has_symbols:
                    print(fr.GREEN + "Strong password/normal")
                    self.salt_for_sha256 = os.urandom(salt_bytes)
                    self.whole_data["master_salt"] = base64.b64encode(self.salt_for_sha256).decode()
                    key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), self.salt_for_sha256, iters)
                    final_fernet_key = base64.urlsafe_b64encode(key)
                    self.Fe = Fernet(final_fernet_key)
                    self.whole_data["Authorized"] = self.Fe.encrypt(b'Verified').decode()
                    self.FileWriter()
                    break
                else:
                    print(fr.RED + f"[!] Cant write weak password security issue!")
    
        else:
            password_input_count = 0
            print(fr.GREEN + "Successfully found master password verifying identity...")
    
            while True:
                master_password = getpass.getpass(fr.YELLOW + "enter password: ")
                SALT_BYTES = base64.b64decode(self.MasterPasswordSalt)
                key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), SALT_BYTES, iters)
                final_fernet_key = Fernet(base64.urlsafe_b64encode(key))
    
                try:
                    Authentication = final_fernet_key.decrypt(self.whole_data["Authorized"].encode())
    
                    if Authentication == b'Verified':
                        self.Fe = final_fernet_key
                        print(fr.GREEN + "[+] Successfully verified identity")
                        print(Style.RESET_ALL)
                        break
    
                except cryptography.fernet.InvalidToken:
                    print(fr.RED + "[!] Authentication failed")
                    print(Style.RESET_ALL)
                    password_input_count += 1
                    print(fr.RED + f"[!] Failed to verify password: {password_input_count} time(s)")
    
                if password_input_count == 5:
                    print(fr.RED + "[!] you have attempted maximum input of password")
                    time.sleep(5)
                    print(fr.RED + "[!] Exiting program to prevent basic brute forcing")
                    print(Style.RESET_ALL)
                    sys.exit()
    
    def AddFirstUserPassIfFirstRun(self):
        passwords = [passwrd for passwrd in self.whole_data if passwrd not in ["Authorized", "master_salt"]]
    
        if len(passwords) == 0:
            print(fr.GREEN + f'[+] Password file is empty adding first user...', Style.RESET_ALL)
            self.FileOpener()
    
            if self.Fe is None:
                print(fr.RED + f"[!] Create master password at first, cant add first user without safety! (choose [1])", Style.RESET_ALL)
                time.sleep(5)
                return
    
            platform = input("enter platform: ")
            username = input(f"enter username for {platform}: ")
            password = getpass.getpass(f"enter password for {username} on platform {platform}: ")
            encrypted_pass = self.Fe.encrypt(password.encode()).decode()
    
            self.whole_data[platform] = {
                "username" : username,
                "password" : encrypted_pass
            }
            print(fr.GREEN + f'[+] Successfully secured password')
            self.FileWriter()
            print(f"[+] Successfully added password in path {self.MainFile}", Style.RESET_ALL)
            time.sleep(5)
            return
    
        else:
            print(fr.RED + f"[!] Cant add 'first' password file already contains password!", Style.RESET_ALL)
            time.sleep(5)
            return
    
    def ViewPasswords(self):
        if not self.Fe:
            print(fr.RED + "[!] Cant enter without master passsword", Style.RESET_ALL)
            return
        if not self.whole_data:
            print(fr.RED + "[!] File is empty, choose option [1] to create first credentials", Style.RESET_ALL)
            return
        print(fr.YELLOW + "[!] Verifying...")
        password_input = getpass.getpass("enter master password: ")
        print(Style.RESET_ALL)
        SALT_BYTES = base64.b64decode(self.MasterPasswordSalt)
        verify_key = hashlib.pbkdf2_hmac("sha256", password_input.encode(), SALT_BYTES, iters)
        verifying_fe = Fernet(base64.urlsafe_b64encode(verify_key))
        try:
            check = verifying_fe.decrypt(self.whole_data["Authorized"].encode())
            if check == b'Verified':
                print(fr.GREEN + "[+] Verification was successful", Style.RESET_ALL)
                for PlatformUser, password in self.whole_data.items():
                    if PlatformUser in ["Authorized", "master_salt"]:
                        continue
                    encrypted_passes = password["password"].encode()
                    decrypted_Passes = verifying_fe.decrypt(encrypted_passes).decode()
                    final_output = {f"{PlatformUser}|{password['username']}" : decrypted_Passes}
                    print(final_output)
        except Exception as err:
            print(fr.RED + f"[!] Access not granted: {err}", Style.RESET_ALL)
    
    def SingleFileCheck(self, file):
        try:
            sd = win32security.GetFileSecurity(str(file), win32security.OWNER_SECURITY_INFORMATION) # security descriptor, gets file info regarding the owner
            sid = sd.GetSecurityDescriptorOwner()
            name, domain, account_type = win32security.LookupAccountSid(None, sid)
            # print("sd: {}".format(sd)) # test line
            # print("sid: {}".format(sid)) # test line
            # print(f"name: {name}\ndoamain: {domain}\naccount_type: {account_type}") # test line
            final_owner = f"user name: {name} || device name: {domain}"
            print(final_owner)
            print(fr.GREEN + f"[+] File: {file.name} || File stats: {file.stat().st_size} B || Owner: {final_owner} || OS info: {platform.system()} {platform.release()} version: {platform.version()}")
        except (pathlib.UnsupportedOperation, NotImplementedError, Exception) as error:
            print(fr.RED + f"[!] caught an error '{error}' if you can fix that, fix it and please report it to creator, if cant then please feel free to report to creator")
            time.sleep(1,5)
            return
        if os.path.getsize(self.MainFile) == 0:
            print(fr.RED + f"[!] File is empty! create master password or add first credentials", Style.RESET_ALL)
            time.sleep(3)
            return
    
    def FileChecker(self):
        if os.path.exists(self.MainFile):
            print(fr.GREEN + "[+] successfully can speed up process...", Style.RESET_ALL)
            files = list(home.iterdir())
            with ccf.ThreadPoolExecutor() as executor:
                result = executor.map(self.SingleFileCheck, files)
            for res in result:
                print(fr.GREEN + "[+] Result: {}".format(res), Style.RESET_ALL)
            if os.path.getsize(self.MainFile) == 0:
                print(fr.RED + f"[!] File is empty! create master password or add first credentials", Style.RESET_ALL)
                time.sleep(3)
                return
            
    def GeneratePass(self):
        big_letts = string.ascii_uppercase
        small_letts = string.ascii_lowercase
        digits = string.digits
        symbols = r"!@#$%^&*()[]\/`~'.,"
        all_together = big_letts + small_letts + digits + symbols
        try:
            user_input_length = input("enter length of generated password(default its 10): ")
            if user_input_length == "":
                user_input_length = 10
            else:
                user_input_length = int(user_input_length)
            if int(user_input_length) < 8:
                print(fr.RED + f"[!] Can't generate {int(user_input_length)} character password too small") 
            pass_chars = [secrets.choice(big_letts), secrets.choice(small_letts), secrets.choice(digits), secrets.choice(symbols)]
            pass_chars += "".join(secrets.choice(all_together) for _ in range (user_input_length - 4))
            secrets.SystemRandom().shuffle(pass_chars)
            final_gen_pass = "".join(pass_chars)
            print(fr.GREEN + f"[+] Successfully generated {user_input_length - 4} character password: {final_gen_pass}", Style.RESET_ALL)
        except ValueError:
            print(fr.RED + f"[!] Unexpected input, expecting int (number) but recieved something else! '{user_input_length}'")
            print(Style.RESET_ALL)
    
    def PasswordStrengthCheck(self):
        big_letts = string.ascii_uppercase
        small_letts = string.ascii_lowercase
        digits = string.digits
        symbols = r"!@#$%^&*()[]\/`~'.,"
        has_upper = False
        has_lower = False
        has_digits = False
        has_symbols = False
        while True:
            password_question = input(fr.YELLOW + "is this password you will check be youe main or just random?(answer: yes/no): ")
            print(Style.RESET_ALL)
            if password_question.lower() == "yes":
                print(fr.YELLOW + "[*] Ok, enter password")
                password_input_1 = getpass.getpass("enter password: ")
                for char in password_input_1:
                    if char in big_letts:
                        has_upper = True
                    if char in small_letts:
                        has_lower = True
                    if char in digits:
                        has_digits = True
                    if char in symbols:
                        has_symbols = True
                if len(password_input_1) == 9 and has_upper and has_lower and has_digits and has_symbols:
                    print(fr.RED + f"[!] password length is normal an acceptable only thing it is being saved by is all symbols characters numbers etc and i hope its now PassW0rd!23")
                    return
                elif has_upper and has_lower and has_symbols and has_digits and len(password_input_1) >= 10:
                    print(fr.GREEN + "[+] congratulations, password is strong and hard to crack")
                    return
                else:
                    print(fr.RED + "[-] password is weak changing is recommended! (might be stronger but missing either number/uppercase/lowercase char or even length small)", Style.RESET_ALL)
                    password_generate = input("Would you like to generate new password for you?(y/n): ")
                    if password_generate.lower() == "y":
                        self.GeneratePass()
                        return
                    else:
                        print(fr.RED + "[!] Exiting")
                        time.sleep(1)
                        return
            elif password_question.lower() == "no":
                print(fr.YELLOW + "[*] Ok, enter password")
                password_input_2 = input("enter password: ")
                for char in password_input_2:
                    if char in big_letts:
                        has_upper = True
                    if char in small_letts:
                        has_lower = True
                    if char in digits:
                        has_digits = True
                    if char in symbols:
                        has_symbols = True
                if len(password_input_2) == 9 and has_upper and has_lower and has_digits and has_symbols:
                    print(fr.RED + f"[!] password length is normal an acceptable only thing it is being saved by is all symbols characters numbers etc and i hope its now PassW0rd!23")
                    return
                elif has_upper and has_lower and has_symbols and has_digits and len(password_input_2) >= 10:
                    print(fr.GREEN + "[+] congratulations, password is strong and hard to crack")
                    return
                else:
                    print(fr.RED + "[-] password is weak changing is recommended! (might be stronger but missing either number/uppercase/lowercase char or even length small)", Style.RESET_ALL)
                    password_generate = input("Would you like to generate new password for you?(y/n): ")
                    if password_generate.lower() == "y":
                        self.GeneratePass()
                        return
                    else:
                        print(fr.RED + "[!] Exiting")
                        time.sleep(1)
                        return
            else:
                print(fr.RED + "[!] expected arguments: yes/no but recieved: {}".format(password_question))
    
    def PasswordFilesafer(self):
        print(fr.YELLOW + "[*] Let's try to make password file safer from other users/groups on your machine\nNote: IT CAN'T MAKE SAFER FROM ADMINISTRATORS OR SYSTEM USER")
        print(fr.YELLOW + "[*] Let's attempt to look at file permissions")
        try:   
            sd1 = win32security.GetFileSecurity(str(self.MainFile), win32security.DACL_SECURITY_INFORMATION) # getting DACL security info
            dacl = sd1.GetSecurityDescriptorDacl() # assiging dacl to security descriptor dacl
            # print(dacl) # test line
            user_SID, Domain, type = win32security.LookupAccountName("", user) # getting readable data instead of printing out bytes
            # print(user_SID) # test line
            # print(Domain) # test line
            # print(type) # test line
            sys_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)
            # print(sys_sid) # test line
            versions = win32security.ACL_REVISION # getting ACL version
            fresh_acl = win32security.ACL() # getting new list ACL
            # print(fresh_acl) # test line
            # print(versions) # test line
            fresh_acl.AddAccessAllowedAce(versions, nc.FILE_ALL_ACCESS, user_SID) # adding new entry to fresh_acl list
            fresh_acl.AddAccessAllowedAce(versions, nc.FILE_ALL_ACCESS, sys_sid) # adding system to perms 
            if dacl is None:
                print(fr.YELLOW + "[🥀] dawg everyone has access to your file")
            sd = win32security.GetFileSecurity(str(self.MainFile), win32security.DACL_SECURITY_INFORMATION) # getting now updated info about file
            sd.SetSecurityDescriptorDacl(1, fresh_acl, 0) # setting new DACL rules
            sd.SetSecurityDescriptorControl(win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED) # telling windows to ignore parent folders
            win32security.SetFileSecurity(str(self.MainFile), win32security.DACL_SECURITY_INFORMATION ,sd) # setting file security
            print(fr.GREEN + "[+] Successfully changed security perms", Style.RESET_ALL)
        except PermissionError as error:
            print(fr.RED + "[!] Cant access forbidden file {}".format(error))
            return
    def AddCredentials(self):
        if "master_salt" in self.whole_data:
            print(fr.GREEN + "[+] Master password was successfully found in data", Style.RESET_ALL)
            self.MasterPasswordSalt = self.whole_data["master_salt"]
        if self.Fe is None:
            print(fr.RED + "[!] Cant add user into database as master password is not present", Style.RESET_ALL)
            self.MasterPassword()
        if os.path.getsize(self.MainFile) == 0:
            print(fr.RED + "[!] File's empty")
            self.AddFirstUserPassIfFirstRun()
            return
        print(fr.GREEN + "[+] Adding credentials into database...")
        platform_for_add_creds = input(fr.YELLOW + "enter platform: ")
        username = input("enter username for platform {}: ".format(platform_for_add_creds))
        password = getpass.getpass("enter password: ")
        print(Style.RESET_ALL)
        self.FileOpener()
        for platf, userdata in self.whole_data.items():
            if platf in ["master_salt", "Authorized"]:
                continue
            act_usern = userdata.get("username")
            if platform_for_add_creds == platf and username == act_usern:
                while True:
                    print(fr.RED + "[!] same credentials are found already would you like to overwrite them? (y/n)", Style.RESET_ALL)
                    user_input_questi = input(fr.YELLOW + "enter y/n: ")
                    print(Style.RESET_ALL)
                    if user_input_questi.lower() == "y":
                        encrypted_data = self.Fe.encrypt(password.encode()).decode()
                        self.whole_data[platform_for_add_creds] = {
                            "username" : username,
                            "password" : encrypted_data
                        }
                        self.FileWriter()
                        return
                    elif user_input_questi.lower() == "n":
                        print(fr.RED + "[!] Exiting", Style.RESET_ALL)
                        break
                    else:
                        print(fr.RED + "Unexpected argumet: '{}' while expecting y or n".format(user_input_questi), Style.RESET_ALL)
            else:
                encrypted_stuff = self.Fe.encrypt(password.encode()).decode()
                self.whole_data[platform_for_add_creds] = {
                    "username" : username,
                    "password" : encrypted_stuff
                }
                self.FileWriter()
                return
        
Password_Manager = PasswordManager()
while True:
    print(Style.RESET_ALL)
    print(fr.CYAN + "[1] Create Master Password",
          fr.CYAN + "\n[2] add First Password If New User ",
          fr.CYAN + "\n[3] Checking If File Exists",
          fr.CYAN + "\n[4] View Passwords (Authorized people only! )",
          fr.CYAN + "\n[5] Generate password",
          fr.CYAN + "\n[6] Check password's strength",
          fr.CYAN + "\n[7] Making password file safe",
          fr.CYAN + "\n[8] Add Credentials",
          fr.CYAN + "\n[9] Exit")
    print(Style.RESET_ALL)
    print(fr.YELLOW + "Always choose [1] when running script to unlock fully password manager!",Style.RESET_ALL)
    print(fr.RED + "[!] ALWAYS REMEMBER MASTER PASSWORD OR WRITE IT DOWN SOMEWHERE SAFE BECAUSE IF ITS LOST/FORGOTTEN YOU CAN NO LONGER RECOVER PASSWORD NOT EVEN OWNER AND OWNER TAKES NO RESPONSIBILITY IN THAT", Style.RESET_ALL)
    print('\n', fr.YELLOW + "Choose (1/2... e.g. must be number not with '[]')", Style.RESET_ALL)
    user_input = input("enter number: ")
    if user_input == "1":
        Password_Manager.MasterPassword()
    elif user_input == "2":
        Password_Manager.AddFirstUserPassIfFirstRun()
    elif user_input == "3":
        Password_Manager.FileChecker()
    elif user_input == "4":
        Password_Manager.ViewPasswords()
    elif user_input == "5":    
        Password_Manager.GeneratePass()
    elif user_input == "6":        
        Password_Manager.PasswordStrengthCheck()
    elif user_input == "7":
        Password_Manager.PasswordFilesafer()
    elif user_input == "8":
        Password_Manager.AddCredentials()
    elif user_input == "9":
        break
    else:
        print(fr.RED + f"[!] Unxpected argument: '{user_input}'")
        print(fr.RED + "IllegalArgumentError", Style.RESET_ALL)
        
        
        
        
