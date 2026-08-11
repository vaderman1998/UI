# -*- encoding: utf-8 -*-
"""
License: MIT
Copyright (c) 2019 - present AppSeed.us
"""
 
import hashlib, binascii, os

# Inspiration -> https://www.vitoshacademy.com/hashing-passwords-in-python/

def hash_pass( password ):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash) # return bytes

def verify_pass(provided_password, stored_password):
    """Verify a stored password against one provided by user"""
    """stored_password = stored_password.decode('ascii')
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')"""
    return provided_password == stored_password



def is_admin():
    """Whether the logged-in user holds the admin role reported by FTS."""
    from flask import session

    # sessions created before role support (and servers that do not report a
    # role) default to admin, preserving the previous behavior
    return session.get('role', 'admin') == 'admin'


def admin_required(view):
    """Restrict a view to users whose FTS group grants admin access.

    The UI talks to the FTS API with one shared API key, so per-user
    authorization cannot be delegated to the API and must be enforced here.
    """
    from functools import wraps

    from flask import render_template

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            return render_template('errors/403.html'), 403
        return view(*args, **kwargs)

    return wrapped
