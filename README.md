# Password-Manager-for-windows-1.0
# Python Password Manager (Encrypted Local Storage)

## Overview

This project is a **local encrypted password manager** written in Python.
It securely stores passwords using strong cryptography and protects access using a master password.

All passwords are encrypted using **PBKDF2 + Fernet encryption** and stored locally in a JSON file.

The password database is stored at:

```
~/.pm_data/passwords.json
```

---

## Features

### 🔐 Master Password Protection

* Requires a master password to access stored credentials
* Password must contain:

  * Uppercase letters
  * Lowercase letters
  * Numbers
  * Symbols
  * Minimum 8 characters
* Password verification is encrypted

---

### 🔑 Strong Encryption

Passwords are encrypted using:

* PBKDF2-HMAC-SHA256
* 3,500,000 iterations
* 64-byte random salt
* Fernet symmetric encryption

Key derivation:

```
PBKDF2-HMAC-SHA256(master_password + salt)
```

Encryption:

```
Fernet(key)
```

This protects stored passwords even if the JSON file is stolen.

---

### 📁 Automatic Secure Storage

The program automatically creates:

```
~/.pm_data/
```

and:

```
passwords.json
```

if they do not exist.

---

### 👤 Password Storage Format

Example structure:

```
{
    "master_salt": "...",
    "Authorized": "...",
    "GitHub": {
        "username": "user123",
        "password": "ENCRYPTED_DATA"
    },
    "Discord": {
        "username": "user456",
        "password": "ENCRYPTED_DATA"
    }
}
```

Passwords are never stored in plaintext.

---

## Menu Options

### 1 — Create Master Password

Creates or unlocks the master password.

Must be done first.

---

### 2 — Add First Password

Adds the first credential if database is empty.

---

### 3 — File Check

Checks password file status and ownership.

Displays:

* File size
* Owner
* OS information

---

### 4 — View Passwords

Requires master password verification.

Decrypts and displays stored credentials.

---

### 5 — Generate Password

Generates strong random passwords using:

* Uppercase
* Lowercase
* Numbers
* Symbols

Uses Python's `secrets` module.

---

### 6 — Password Strength Checker

Analyzes password strength.

Checks:

* Length
* Symbols
* Numbers
* Uppercase
* Lowercase

Can generate stronger password if needed.

---

### 7 — Secure Password File (Windows)

Restricts file permissions using Windows ACL.

Allows access only to:

* Current user
* SYSTEM account

Prevents other users from reading passwords.

---

### 8 — Add Credentials

Adds new encrypted credentials.

Supports overwriting existing entries.

---

### 9 — Exit

Closes program.

---

## Security Design

### Encryption

Uses:

```
PBKDF2-HMAC-SHA256
```

Iterations:

```
3,500,000
```

Salt:

```
64 bytes random
```

Encryption:

```
Fernet (AES-128 CBC + HMAC)
```

---

## Dependencies

Required libraries:

```
cryptography
colorama
pywin32
```

Install:

```
pip install cryptography colorama pywin32
```

---

## Security Notes

* Master password cannot be recovered if lost
* Password file is encrypted
* Offline brute-force is slowed by PBKDF2 iterations
* File permissions can be restricted
* Passwords are never stored plaintext

---

## Platform Support

Tested on:

* Windows (Full support)
* Linux (Partial support)

Windows-only features:

* File permission hardening
* Ownership detection

---

## Author Notes

This project was designed as a **learning project for cybersecurity and cryptography**.

It demonstrates:

* Secure password storage
* Key derivation
* Encryption
* File permission security
* Authentication systems

---

## Warning

If you forget the master password:

Passwords cannot be recovered.

Even the creator cannot decrypt them.

---

## Future Improvements

Possible upgrades:

* GUI interface
* Auto-lock timer
* Backup encryption
* Hardware key support
* Hash-based password lookup
* Clipboard copy feature
* Search function

---

