from flask_mysqldb import MySQL
import bcrypt

from __init__ import app, mysql
from views import error

from os import path, urandom

from cryptography                              import x509
from cryptography.exceptions                   import InvalidSignature
from cryptography.hazmat.primitives            import serialization, asymmetric, hashes, padding
from cryptography.hazmat.primitives.ciphers    import Cipher, algorithms, modes

import base64
import json
import logging
import requests

requests.packages.urllib3.disable_warnings()
logging.basicConfig(level=logging.DEBUG)

AUTH_SERVER = app.config["AUTH_SERVER"]
AUTH_CERT: x509.Certificate
CA_CERT:   x509.Certificate
WEB_CERT:   x509.Certificate
SECRET_KEY: bytes
PRIVATE_KEY: bytes

with open(app.config["MY_PRIV_PATH"], "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

with open(app.config["CA_CERT_PATH"], "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

with open(app.config["AUTH_CERT_PATH"], "rb") as f:
    AUTH_CERT = x509.load_pem_x509_certificate(f.read())

with open(app.config["MY_CERT_PATH"], "rb") as f:
    WEB_CERT = x509.load_pem_x509_certificate(f.read())

if not path.exists(app.config["MY_SECRET_KEY"]):
    SECRET_KEY = urandom(32)
    keyEncoded = WEB_CERT.public_key().encrypt(SECRET_KEY, asymmetric.padding.PKCS1v15())
    with open(app.config["MY_SECRET_KEY"], "wb") as f:
        f.write(keyEncoded)
else:
    with open(app.config["MY_SECRET_KEY"], "rb") as f:
        SECRET_KEY = PRIVATE_KEY.decrypt(f.read(), asymmetric.padding.PKCS1v15())


# INIT DB
def init_db():
    cur = mysql.connection.cursor()
    cur.execute("DROP DATABASE IF EXISTS %s;" % app.config['MYSQL_DB'])
    cur.execute("CREATE DATABASE %s;" % app.config['MYSQL_DB'])
    cur.execute("USE %s;" % app.config['MYSQL_DB'])
    cur.execute("DROP TABLE IF EXISTS Users;")
    cur.execute('''CREATE TABLE Users (
                    username VARCHAR(20) NOT NULL,
                    password VARCHAR(60) NOT NULL,
                    name VARCHAR(255),
                    about VARCHAR(2047),
                    photo VARCHAR(255) DEFAULT '{}',
                    PRIMARY KEY (username)
                    );'''.format(app.config['default_photo']))
    cur.execute("INSERT INTO Users(username, password, name, about) VALUES (%s, %s, %s, %s)", ('administrator', '$2b$12$he1RT30LM44MHosa/8hzKO33C7BdXD93t5tpljEgu//iVhiLkmA9W', "Admin", "I have no friends."))
    cur.execute("INSERT INTO Users(username, password, name) VALUES (%s, %s, %s)", ('investor', '$2b$12$Dya4pi6pWLxuZA.MDf5rsOYesCtJizuYLtXxm7gbfsq6PC9uaPLry', "Mr. Smith"))
    cur.execute("INSERT INTO Users(username, password, name, about) VALUES (%s, %s, %s, %s)", ('ssofadmin', '$2b$12$mxbGozDUJ.9je6Vwj/rqqeVh9F2nYvsp5LSM3H6eCE9xZWqzfOdeW', "SSofAdmin", "A 12-year experienced sys-admin that has developed and secured this application."))
    cur.execute("DROP TABLE IF EXISTS Posts;")
    cur.execute('''CREATE TABLE Posts (
                    id int(11) NOT NULL AUTO_INCREMENT,
                    author VARCHAR(20) NOT NULL,
                    content VARCHAR(2047),
                    type ENUM ('Public','Private','Friends') DEFAULT 'Public',
                    created_at timestamp default now(),
                    updated_at timestamp default now() ON UPDATE now(),
                    PRIMARY KEY (id),
                    FOREIGN KEY (author) REFERENCES Users(username)
                    );''')
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('administrator', 'No one will find that I have no secrets.', "Private"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('investor', 'This is a great platform', "Public"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('investor', 'Lets keep it for us but I believe that after this app Instagram is done', "Friends"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('investor', 'TikTok might also be done but do not want ot make this bold claim in Public', "Private"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('SSofAdmin', 'There are no problems with this app. It works perfectly', "Public"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('SSofAdmin', 'Cannot put this app running. Can any of my friends help me', "Friends"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('SSofAdmin', 'Just found a great new thing. Have a look at it. It might be of help. https://www.guru99.com/install-linux.html', "Public"))
    cur.execute("INSERT INTO Posts(author, content, type) VALUES (%s, %s, %s)", ('SSofAdmin', 'This one is also great. https://www.youtube.com/watch?v=oHg5SJYRHA0&', "Public"))
    cur.execute("DROP TABLE IF EXISTS Friends;")
    cur.execute('''CREATE TABLE Friends (
                    id int(11) NOT NULL AUTO_INCREMENT,
                    username1 VARCHAR(20) NOT NULL,
                    username2 VARCHAR(20) NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (username1) REFERENCES Users(username),
                    FOREIGN KEY (username2) REFERENCES Users(username)
                    );''')
    cur.execute("INSERT INTO Friends(username1, username2) VALUES (%s, %s)", ('investor', "SSofAdmin"))
    cur.execute("DROP TABLE IF EXISTS FriendsRequests;")
    cur.execute('''CREATE TABLE FriendsRequests (
                    id int(11) NOT NULL AUTO_INCREMENT,
                    username1 VARCHAR(20) NOT NULL,
                    username2 VARCHAR(20) NOT NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (username1) REFERENCES Users(username),
                    FOREIGN KEY (username2) REFERENCES Users(username)
                    );''')
    cur.execute("INSERT INTO Users(username, password, name, about) VALUES (%s, %s, %s, %s)", ('randomjoe1', '$2b$12$dN846aDcJxKZluqI.eV2ieDqB6sMBio7spjpB8Umx/Iu15EMSCcOm', "Random Joe Smith1", "I am the real Random Joe"))
    cur.execute("INSERT INTO Users(username, password, name) VALUES (%s, %s, %s)", ('randomjoe2', '$2b$12$v9zNGO7sQhmRfzLOdekVJuJenZEmxu8ks2UvMRXpRYPBF7oJ3YTW2', "Random Joe Smith2"))
    cur.execute("INSERT INTO Users(username, password, name) VALUES (%s, %s, %s)", ('randomjoe3', '$2b$12$.1pzGkm746TIgyE9fyNCye2FMDIDHhnfzj6M/KXXX..S7vAf1iAm.', "Random Joe Smith3"))
    cur.execute("INSERT INTO Users(username, password, name) VALUES (%s, %s, %s)", ('randomjoe4', '$2b$12$Ee07KbvA5F.5N/oEduPN7uneja/wAyx.ghSlhkHNKcVvacAeELCtm', "Random Joe Smith4"))
    cur.execute("INSERT INTO FriendsRequests(username1, username2) VALUES (%s, %s)", ('randomjoe1', "investor"))
    cur.execute("INSERT INTO FriendsRequests(username1, username2) VALUES (%s, %s)", ('randomjoe2', "investor"))
    cur.execute("INSERT INTO FriendsRequests(username1, username2) VALUES (%s, %s)", ('randomjoe3', "investor"))
    cur.execute("INSERT INTO FriendsRequests(username1, username2) VALUES (%s, %s)", ('randomjoe4', "investor"))
    cur.execute("DROP TABLE IF EXISTS Authorizations;")
    cur.execute('''CREATE TABLE Authorizations (
                    id int(11) NOT NULL AUTO_INCREMENT,
                    username VARCHAR(20) NOT NULL,
                    json VARCHAR(2750),
                    hash VARCHAR(88),
                    iv VARCHAR(24),
                    PRIMARY KEY (id),
                    FOREIGN KEY (username) REFERENCES Users(username)
                    );''')


    mysql.connection.commit()
    cur.close()


# SELECT QUERIES
def get_all_results(q):
    cur = mysql.connection.cursor()
    cur.execute(q)
    mysql.connection.commit()
    data = cur.fetchall()
    cur.close()
    return data


# SELECT QUERIES PREPARED STATEMENTS
def get_all_results_prepared(q, values=()):
    cur = mysql.connection.cursor()
    cur.execute(q, values)
    mysql.connection.commit()
    data = cur.fetchall()
    cur.close()
    return data


# UPDATE and INSERT QUERIES
def commit_results(q):
    cur = mysql.connection.cursor()
    cur.execute(q)
    mysql.connection.commit()
    cur.close()


# UPDATE and INSERT QUERIES PREPARED STATEMENTS
def commit_results_prepared(q, values=()):
    cur = mysql.connection.cursor()
    cur.execute(q, values)
    mysql.connection.commit()
    cur.close()


##### Returns a user for a given username
### in: username
### out: User
def get_user(username):
    q = "SELECT * FROM Users WHERE BINARY username = %s"
    values = (username,)

    logging.debug("get_user query: %s" % q)
    data = get_all_results_prepared(q, values)

    if len(data) == 1:
        user = User(*(data[0]))
        return user
    else:
        logging.debug("get_user: Something wrong happened with (username):(%s)" % (username))
        return None

##### Returns a boolean stating if code was OK or not
### in: username, code
### out: boolean (status)
def authenticate_user(username, code):
    response = requests.get(AUTH_SERVER + "/authenticate/" + username + "/" + code)
    if response.status_code == 200:
        response = json.loads(response.text)
        sign = base64.b64decode(response["signature"])
        body = response["body"]

        msg = (body["username"] + str(body["ts"]) + body["status"]).encode()

        try:
            AUTH_CERT.public_key() \
                     .verify(sign,
                             msg,
                             asymmetric.padding.PKCS1v15(),
                             hashes.SHA256())

            if body["status"] == "OK" and body["username"] == username:
                return True
        except InvalidSignature:
            return False
    return False

##### Returns a user for a given pair username:password
### in: username, password
### out: User
def login_user(username, password):
    q = "SELECT password FROM Users WHERE BINARY username = %s"
    values = (username,)
    data = get_all_results_prepared(q, values)

    if len(data) != 1:
        logging.debug("login_user: Something wrong happened with (username, password):(%s %s)" % (username, password))
        return None

    hashed = data[0][0]
    if bcrypt.checkpw(password.encode(), hashed.encode()):
        q = "SELECT * FROM Users WHERE BINARY username = %s"
        values = (username,)
        data = get_all_results_prepared(q, values)

        if len(data) == 1:
            user = User(*(data[0]))
            return user
        else:
            logging.debug("login_user: Something wrong happened with (username, password):(%s %s)" % (username, password))
            return None
    else:
        logging.debug("login_user: Something wrong happened with (username, password):(%s %s)" % (username, password))
        return None

##### Registers a new user with a given pair username:password
### in: username, password
### out: User
def register_user(username, password):
    q = "INSERT INTO Users (username, password) VALUES (%s, %s)"
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt).decode()

    logging.debug("register_user query: %s" % q)
    commit_results_prepared(q, (username, hashed))
    return User(username, hashed)


##### Updates a user with the given characteristics
### in: username, new_name, new_password, new_about, new_photo
### out: User
def update_user(username, new_name, new_password, new_about, new_photo):
    q = "UPDATE Users "
    q += "SET password=%s, name=%s, about=%s, photo=%s "
    q += "WHERE BINARY username = %s"

    values = (new_password, new_name, new_about, new_photo, username)

    logging.debug("update_user query: %s" % q)
    commit_results_prepared(q, values)
    return User(username, new_password, new_name, new_about, new_photo)


##### Creates a new post
### in: username, new_content, type
### out: True
def new_post(username, new_content, type):
    q = "INSERT INTO Posts (author, content, type)"
    q+= " VALUES (%s, %s, %s)"

    values = (username, new_content, type)
    logging.debug("new_post query: %s" % q)
    commit_results_prepared(q, values)
    return True


##### Gets the post with the given post_id
### in: post_id
### out: Post
def get_post(post_id):
    q = "SELECT * FROM Posts"
    q+= " WHERE id = %s"
    value = (post_id, )

    logging.debug("get_post query: %s" % q)
    data = get_all_results_prepared(q, value)

    if len(data) == 1:
        post = Post(*(data[0]))
        return post
    else:
        logging.debug("get_post: Something wrong happened with (post_id):(%d)" % (post_id))
        return None


##### Edits the post with the given post_id
### in: post_id, new_content, type
### out: True
def edit_post(post_id, new_content, type):
    q = "UPDATE Posts"
    q+= " SET content=%s, type=%s"
    q+= " WHERE id = %s"
    values = (new_content, type, post_id)

    logging.debug("edit_post query: %s" % q)
    commit_results_prepared(q, values)
    return True


##### Returns all posts of a user, from his friends, or public
### in: username
### out: List of Posts_to_show
def get_all_posts(username):
    q = "SELECT Posts.id, Users.username, Users.name, Users.photo, Posts.content, Posts.type, Posts.created_at"
    q+= " FROM Users INNER JOIN Posts"
    q+= " ON Users.username = Posts.author"
    q+= " WHERE BINARY Posts.author = '%s'" % (username)
    q+= " OR (Posts.type = 'Public')"
    q+= " OR (Posts.type = 'Friends' AND BINARY Posts.author IN"
    q+= " (SELECT username1 from Friends WHERE BINARY username2 = '%s'" % (username)
    q+= "  UNION SELECT username2 from Friends WHERE BINARY username1 = '%s'))" % (username)

    logging.debug("get_all_posts query: %s" % q)
    data = get_all_results(q)
    posts_to_show = []

    for x in data:
        posts_to_show.append(Post_to_show(*x))

    logging.debug("get_all_posts: %s" % (posts_to_show))
    return posts_to_show


##### Creates a new friend request
### in: username (requester), username (new_friend)
### out: True
def new_friend_request(username, new_friend):
    q = "INSERT INTO FriendsRequests (username1, username2) VALUES (%s, %s)"
    values = (username, new_friend)

    logging.debug("new_friend_request query: %s" % q)
    commit_results_prepared(q, values)
    return True


##### Checks if there is a friend request pending
### in: username (requester), username (new_friend)
### out: data
def is_request_pending(requester, username):
    q = "SELECT username1 FROM FriendsRequests  WHERE BINARY username1 = %s AND BINARY username2 = %s"
    values = (requester, username)

    logging.debug("is_request_pending query: %s" % q)
    data = get_all_results_prepared(q, values)
    return data


#### Returns pending friendship requests for the user
### in: username (new_friend)
### out: List of Users
def get_pending_requests(username):
    q = "SELECT * from Users WHERE BINARY username IN (SELECT username1 FROM FriendsRequests  WHERE BINARY username2 = %s)"
    value = (username,)

    logging.debug("get_pending_requests query: %s" % q)
    data = get_all_results_prepared(q, value)
    users = []

    for x in data:
        users.append(User(*x))

    logging.debug("get_pending_requests: %s" % (users))
    return users


##### Accepts a pending friendship requests for the user
### in: username, accept_friend (requester)
### out: True
def accept_friend_request(username, accept_friend):
    cursor = mysql.connection.cursor()
    q = "INSERT INTO Friends (username1, username2) VALUES (%s, %s);"
    values = (accept_friend, username)

    logging.debug("accept_friend_request query1: %s" % q)
    cursor.execute(q, values)

    q = "DELETE FROM FriendsRequests WHERE BINARY username1=%s AND BINARY username2=%s;"

    logging.debug("accept_friend_request query2: %s" % q)
    cursor.execute(q, values)
    mysql.connection.commit()

    cursor.close()
    return True


##### Returns all friends of user that match the search query
### in: username, search_query
### out: List of Users
def get_friends(username, search_query):
    q = "SELECT * FROM Users"
    q+= " WHERE BINARY username LIKE %s"
    q+= " AND username IN"
    q+= " (SELECT username1 FROM Friends"
    q+= "  WHERE BINARY username2 = %s"
    q+= "  UNION SELECT username2 FROM Friends"
    q+= "  WHERE BINARY username1 = %s)"

    logging.debug("get_friends query: %s" % q)
    values = ("%%" + search_query + "%%", username, username)
    data = get_all_results_prepared(q, values)
    friends = []

    for x in data:
        friends.append(User(*x))

    logging.debug("get_friends: %s" % (friends))
    return friends


##### Returns the usernames of all friends of user
### in: username
### out: List of usernames
def get_friends_aux(username):
    q = "SELECT username2 FROM Friends"
    q+= " WHERE BINARY username1 = '%s'" % (username)
    q+= " UNION"
    q+= " SELECT username1 FROM Friends"
    q+= " WHERE BINARY username2 = '%s'" % (username)

    logging.debug("get_friends_aux query: %s" % q)
    data = get_all_results(q)
    friends = []

    for x in data:
        friends.append(x[0])

    logging.debug("get_friends_aux query: %s" % q)
    return friends

def create_authorization(username, update, hash, iv):
    q = "INSERT INTO Authorizations (username, json, hash, iv) VALUES (%s, %s, %s, %s)"

    logging.debug("insert_authorization query: %s" % q)
    commit_results_prepared(q, (username, json.dumps(update), hash, base64.b64encode(iv).decode() if iv else None))
    if not send_authorization(username, hash, update["ts"]):
        q = "DELETE FROM Authorizations WHERE username=%s AND hash=%s"
        commit_results_prepared(q,(username, hash))
        raise Exception("error contacting auth")

def get_authorizations(username):
    q = "SELECT * FROM Authorizations WHERE username=%s ORDER BY id DESC"

    logging.debug("get_authorizations query: %s" % q)
    data = get_all_results_prepared(q, (username, ))
    authorizations = []

    for x in data:
        authorizations.append(Authorization(*x))

    logging.debug("get_authorizations query: %s" % q)
    return authorizations

def get_authorization(username, hash):
    q = "SELECT * FROM Authorizations WHERE username=%s AND hash=%s"

    logging.debug("get_authorization query: %s" % q)
    data = get_all_results_prepared(q, (username, hash))
    if len(data) == 1:
        authorization = Authorization(*(data[0]))
        return authorization
    else:
        logging.debug("get_authorization: Something wrong happened with (username, hash):(%s, %s)" % (username, hash))
        return None

def send_authorization(username, hash, ts):
    to_sign = username + hash + ts
    signature = sign_to_b64(to_sign.encode())

    try:
        response = requests.post(AUTH_SERVER + "/authorize/", json = {"username": username, "hash": hash, "ts": ts, "signature": signature}, timeout=5)
        if response.status_code == 201:
            return True
        else:
            return False
    except Exception as e:
        return False

def authorize(authorization):
    user = get_user(authorization.username)
    update_json = authorization.update
    if not user or not update_json:
        return False

    user.name = update_json["name"] if "name" in update_json else user.name
    if "password" in update_json:
        salt = bcrypt.gensalt()
        user.password = bcrypt.hashpw(update_json["password"].encode(), salt).decode()
    user.about = update_json["about"] if "about" in update_json else user.about
    user.photo = update_json["photo"] if "photo" in update_json else user.photo

    user = update_user(user.username, user.name, user.password, user.about, user.photo)
    if user:
        delete_authorization(authorization)
        return True
    return False

def delete_authorization(authorization):
    q = "DELETE FROM Authorizations WHERE username=%s AND hash=%s"
    logging.debug("delete_authorization query: %s" % q)
    commit_results_prepared(q,(authorization.username, authorization.hash))
    return True

def cipher_aes_to_b64(plain, iv):
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # add padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plain) + padder.finalize()
    ciphertxt = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertxt).decode()

def decipher_aes_from_b64(b64_text, iv):
    ciphered_text = base64.b64decode(b64_text.encode())
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphered_text) + decryptor.finalize()

    # remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    deciphered_text = unpadder.update(decrypted) + unpadder.finalize()
    return deciphered_text.decode()

def digest_text_to_b64(plain):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(plain.encode())
    return base64.b64encode(digest.finalize()).decode()

def sign_to_b64(plain):
    signature = PRIVATE_KEY.sign(plain,
                                 asymmetric.padding.PKCS1v15(),
                                 hashes.SHA256())
    return base64.b64encode(signature).decode()

def verify_auth_signature(to_verify, signature):
    return AUTH_CERT.public_key().verify(signature, to_verify, padding.PKCS1v15(), hashes.SHA256())

##### class User
class User():
    def __init__(self, username, password, name='', about='', photo=''):
        self.username = username
        self.password = password # @TODO: Hash me! PLEASE!
        self.name = name
        self.about = about
        self.photo = photo

    def __repr__(self):
        return '<User: username=%s, password=%s, name=%s, about=%s, photo=%s>' % (self.username, self.password, self.name, self.about, self.photo)


##### class Post
class Post():
    def __init__(self, id, author, content, type, created_at, updated_at):
        self.id = id
        self.author = author
        self.content = content
        self.type = type
        self.created_at = created_at
        self.updated_at = updated_at

    def __repr__(self):
        return '<Post: id=%s, author=%s, content=%s, type=%s, created_at=%s, updated_at=%s>' % (self.id, self.author, self.content, self.type, self.created_at, self.updated_at)


##### class Post_to_show (includes Users and Posts information)
class Post_to_show():
    def __init__(self, id, author, name, photo, content, type, created_at):
        self.id = id
        self.author = author
        self.name = name
        self.photo = photo
        self.content = content
        self.type = type
        self.created_at = created_at

    def __repr__(self):
        return '<Post_to_show: id=%d, author=%s, name=%s, photo=%s, content=%s, type=%s, created_at=%s>' % (self.id, self.author, self.name, self.photo, self.content, self.type, self.created_at)


##### class Authorization (includes Users changes authorizations)
class Authorization():
    def __init__(self, id, username, update, hash, iv):
        self.id = id
        self.username = username
        self.update = json.loads(update)
        if "password" in self.update:
            self.update['password'] = decipher_aes_from_b64(self.update['password'], base64.b64decode(iv))
        self.hash = hash
        self.ts = self.update['ts']

    def __repr__(self):
        return '<Auhotization: id=%d, username=%s, json=%s, hash=%s, ts=%s>' % (self.id, self.username, self.json, self.hash, self.ts)
