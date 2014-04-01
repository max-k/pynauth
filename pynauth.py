#! /usr/bin/env python
# -*- coding: utf8 -*-

#
# pynauth : LDAP Authentication module for
# nginx POP/IMAP/SMTP proxy
#
# author : Thomas Sarboni <max-k@post.com>
#
# licence : GPLv3
#

# modules import

import sys, re, math, ldap
from flask import Flask, request, make_response
from werkzeug.exceptions import BadRequest

# Base configuration

# LDAP server URI
LDAP_URI = "ldap://172.16.21.86"

# Base DN of the LDAP search
# You can use %d flag to insert user mailbox domain
BASE_DN = "ou=users,dc=%d,dc=local"

# Field to match for user login
LOGIN_FIELD = "uid"

# Attributes to get from LDAP directory
# If port = None, default ports will be used
ATTRS_MAP = {"mailbox": "mailBox",
             "mailserver": "mailBoxServer",
             "port": None}

# Default domain to add to a short login
DEFAULT_DOMAIN = "example.com"

# Default ports to use if they're not in directory
DEFAULT_PORTS = {'imap':144,
                 'pop':110,
                 'smtp':25}

# Admins wich wants to receive mail notifications
# Notifications disabled if empty
ADMINS = ['admin1@example.com', 'admin2@example.com']

# SMTP server to relay noptifications to
SMTP_RELAY = "smtp.example.com"

# Sender of notification emails
SMTP_SENDER = "mail_auth@example.com"

# Flask Init

app = Flask(__name__)

# debug mode

app.debug = True

# Error handling

@app.errorhandler(400)
def page_not_found(e):
    return("Bad request.", 403)

@app.errorhandler(404)
def page_not_found(e):
    return("Page not found.", 404)

@app.errorhandler(500)
def internal_server_error(e):
    return("Internal server error.", 500)

# SMTP Exceptions logger

if not app.debug:
    import logging
    from logging.handlers import SMTPHandler
    mail_handler = SMTPHandler(SMTP_RELAY,
                               SMTP_SENDER,
                               ADMINS,
                               'Internal server error.')
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)

# Main route

@app.route('/auth')
@app.route('/')
def endpoint():
    '''
    Try to authenticate a user using elements in headers
    Client-Ip : Client's IP address (logging purpose)
    Auth-User : Client username
    Auth-Pass : Client password
    Auth-Login-Attempt : Number of attemps since last failure
    '''
    status = None
    cnx = None
    host = None
    headers = {}

    # Get informations in HTTP headers

    ip = request.headers.get('Client-Ip', None)
    username = request.headers.get('Auth-User', None)
    password = request.headers.get('Auth-Pass', None)
    protocol = request.headers.get('Auth-Protocol', None)
    attempt = int(request.headers.get('Auth-Login-Attempt', None))

    # Raise exception if incorrect headers has been passed

    status = "Bad headers"
    if not username or not password or not protocol:
        raise(BadRequest)

    # Recover domain from login or default domain if applicable

    login, domain = get_login(username)

    # Insert domain in base_dn if needed

    base_dn = BASE_DN
    if domain:
        pattern = re.compile("%d")
        base_dn = re.sub(pattern, domain, base_dn)
    user_dn = "%s=%s,%s" % (LOGIN_FIELD, login, base_dn)

    # Debug to stderr if debug=True

    if app.debug:
        sys.stderr.write("\nlogin : %s\n" % (login))
        sys.stderr.write("domain : %s\n" % (domain))
        sys.stderr.write("dn : %s\n" % (user_dn))

    # Get LDAP infos

    cnx, status = ldap_connect(LDAP_URI)

    if status and app.debug:
        sys.stderr.write("Unable to connect to LDAP : %s\n" % (status))

    if not status:
        status = authenticate(cnx, user_dn, password)
        if status and app.debug:
            sys.stderr.write("Unable to authenticate to LDAP : %s\n" % (status))

    if not status:
        email, host, port, status = get_host(cnx, base_dn, login, protocol)
        if status and app.debug:
            sys.stderr.write("Unable to get user's mail host : %s\n" % (status))

    if not status:
        host_proto, host_ip, host_port = host.split(':')

        if app.debug:
            sys.stderr.write("host : %s\n" % (host_ip))

        if host_ip == "127.0.0.1":
            host_ip = LDAP_URI.split('//')[1]

        status = 'OK'
        headers["Auth-Server"] = "172.16.21.88" #host_ip
        headers["Auth-Port"] = port

    headers["Auth-Wait"] = check_attempt(attempt)
    headers["Auth-Status"] = status
    headers["Auth-User"] = username
    headers["Remote-Ip"] = ip

    response = make_response()
    for header in headers:
        response.headers[header] = headers[header]

    # Debug if needed

    if app.debug:
        sys.stderr.write("HTTP Headers :\n%s" % (response.headers))

    return(response)

# Authentication related functions

def get_login(username):
    '''
    get login and domain based on short or long username
    '''
    splitted_username = username.split('@')
    if len(splitted_username) == 1:
        login = username
        domain = DEFAULT_DOMAIN
    else:
        login = splitted_username[0]
        domain = splitted_username[1]
    return(login, domain)

def ldap_connect(URI):
    '''
    Generate an ldap connexion and return it with an status
    '''
    cnx = None
    status = None
    try:
        cnx = ldap.initialize(URI)
    except ldap.LDAPError:
        exc = sys.exc_info()[1]
        status = exc['desc']
    return(cnx, status)

def authenticate(cnx, user_dn, password):
    '''
    Try to authenticate a user using ldap connexion
    '''
    status = None
    try:
        cnx.simple_bind_s(user_dn, password)
    except ldap.INVALID_CREDENTIALS:
        status = 'Invalid credentials'
    return(status)

def get_host(cnx, base_dn, login, protocol):
    '''
    Return user's email and backend server in the form SMTP:IP
    '''
    email = None
    host = None
    status = None
    scope = ldap.SCOPE_SUBTREE
    filter = "%s=%s" % (LOGIN_FIELD, login)
    attrs = [ATTRS_MAP[attr] for attr in ATTRS_MAP if ATTRS_MAP[attr]]
    id = cnx.search(base_dn, scope, filter, attrs)

    while True:
        type, data = cnx.result(id, 0)
        if (data == []):
            break
            status = 'Host not found'
        if type == ldap.RES_SEARCH_ENTRY:
            email = data[0][1][ATTRS_MAP['mailbox']][0]
            host = data[0][1][ATTRS_MAP['mailserver']][0]
            port = DEFAULT_PORTS[protocol]
            if 'port' in attrs:
                port = data[0][1][ATTRS_MAP['port']][0]
    return(email, host, port, status)

def check_attempt(attempt):
    '''
    Return wait time (in seconds) based on number failed attempts
    '''
    if not attempt or attempt > 20:
        return(3600)
    if attempt > 10:
        return(60)
    return(3)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

