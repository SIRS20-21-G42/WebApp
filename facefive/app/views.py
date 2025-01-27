from flask import render_template, request, session, redirect, url_for, flash, make_response, escape, Response
from flask_mysqldb import MySQL
import random, string, bcrypt
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest

from cryptography.exceptions import InvalidSignature

from time import time
from os import urandom
import base64
import json

from __init__ import app, mysql, csrf
import model

import logging
logging.basicConfig(level=logging.DEBUG)

@app.before_request
def filter_scanner_boys():
     user_agent = request.headers.get('User-Agent')
     if "sqlmap" in user_agent:
          return abort(404)


##### auxiliar to render errors
def error(msg):
    return render_template('error_response.html', msg = msg)


##### initializes db
@app.route('/init', methods=['GET', 'POST'])
def init():
    model.init_db()
    flash("Initialisation DONE!", 'error')
    return redirect(url_for('login'))


##### home
### shows all posts if user is logged in
### redirects to login otherwise
@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)
        logging.debug("user in homepage: (%s)" % user)
        try:
            posts_to_show = model.get_all_posts(username)
        except Exception as e:
            logging.debug("home: Found exception(%s)" % e)
            return error("Error: Could not load posts")

        if user:
            return render_template('home.html', current_user=user, posts=posts_to_show)
    return redirect(url_for('login'))


##### login user
### in[POST]: username, password
### redirects to home if login is succesful
### redirects to login otherwise
@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    username = None
    user     = None
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = request.form['password']
    code     = request.form['code']
    logging.debug("login: Trying (%s, %s, %s)" % (username, password, code))

    if username == "" or password == "" or code == "":
        flash("You need to provide a 'username', a 'password' and a 'code' to login.", 'error')
        return redirect(url_for('login'))

    try:
        user = model.login_user(username, password)
    except Exception as e:
        logging.debug("login: Found exception(%s)" % e)
        return error("Error: Could not login")

    if not user:
        flash('Username or Password are invalid', 'error')
        return redirect(url_for('login'))

    if not model.authenticate_user(username, code):
        logging.debug("login: failed code authentication")
        return error("Error: Could not login")

    logging.debug("login: Succesfull (%s, %s)" % (username, password))
    session['username'] = username
    return redirect(url_for('home'))


##### register a new user
### in[POST]: username, password
### redirects to home if registration is succesful
### redirects to register otherwise
@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    username = None
    user     = None
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form['username']
    password = request.form['password']
    code     = request.form['code']
    logging.debug("register: Trying (%s, %s, %s)" % (username, password, code))

    if username == "" or password == "" or code == "":
        flash("You need to provide a 'username', a 'password' and a 'code' to register.", 'error')
        return redirect(url_for('register'))

    try:
        user = model.get_user(username)
    except Exception as e:
        logging.debug("register1: Found exception(%s)" % e)
        return error("Error: Could not register user")

    if user:
        flash("User '%s' already exists." % user.username, 'error')
        return redirect(url_for('register'))

    try:
        if model.authenticate_user(username, code):
           user = model.register_user(username, password)
        else:
             logging.debug("register: failed code authentication")
             return redirect(url_for('register'))
    except Exception as e:
        logging.debug("register2 Found exception(%s)" % e)
        return error("Error: Could not register user")

    logging.debug("register: Succesfull (%s, %s)" % (username, password))
    session['username'] = username
    return redirect(url_for('home'))


##### logout
### removes the username from the session if it is there
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


##### show the user profile
### in[GET]: username
### shows the user profile if user is logged in
### redirects to login otherwise
@app.route('/profile', methods=["GET"])
def profile():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)
        if user:
            return render_template('profile.html', current_user=user)
    return redirect(url_for('login'))


##### update user profile
### in[POST]: username, name, about, photo, current_password, new_password
### updates the user profile
### redirects to profile
@app.route('/update_profile', methods=["POST"])
@csrf.exempt
def update_profile():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    logging.debug("update_profile: Trying (%s)" % (username))

    if user.username == "administrator":
        flash("Profile updating has been disabled for user admin.", 'error')
        return render_template('profile.html', current_user=user)

    update = { "username": user.username, "ts":  str(int(time()))}

    new_name = request.form['name']
    if not new_name:
        new_name = user.name
    else:
        update["name"] = new_name

    new_about = request.form['about']
    if new_about != user.about and \
        not (new_about == 'None' and not user.about): # specific case when there is no about and it is not added one
        update["about"] = new_about


    new_photo = request.files['photo']
    if not new_photo:
        new_photo_filename = user.photo
    else:
        if not new_photo.filename.endswith(app.config['IMAGE_EXTENSIONS']):
            flash("Wrong file format. Only images allowed", 'error')
            return render_template('profile.html', current_user=user)
        new_photo_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + '_' + secure_filename(new_photo.filename)
        new_photo.save(app.config['photos_folder'] + new_photo_filename)

        logging.debug("update_profile: filename (%s)" % new_photo_filename)
        logging.debug("update_profile: file (%s)" % new_photo)

        update["photo"] = new_photo_filename

    current_password = request.form['currentpassword']

    new_password = request.form['newpassword']
    update_hash: str
    iv = urandom(16)
    try:
        if not new_password:
            new_password = current_password
            update_hash = model.digest_text_to_b64(json.dumps(update, separators=(',', ':')))
            iv = None
        else:
            update['password'] = new_password

            # hash needs to be calculated before password encryption
            update_hash = model.digest_text_to_b64(json.dumps(update, separators=(',', ':')))

            b_64_pass = model.cipher_aes_to_b64(new_password.encode(), iv)
            update['password'] = b_64_pass
    except Exception as e:
        logging.debug("update_profile: Found exception(%s)" % e)
        return error("Error: Could not update the profile")

    if not bcrypt.checkpw(current_password.encode(), user.password.encode()):
        flash("Current password does not match registered password.", 'error')
        return render_template('profile.html', current_user=user)

    # check if there was indeed an update to the user
    if len(update.keys()) == 2:
        flash("Please perform an update to your profile.", 'error')
        return render_template('profile.html', current_user=user)

    try:
        model.create_authorization(username, update, update_hash, iv)
    except Exception as e:
        logging.debug("update_profile: Found exception(%s)" % e)
        return error("Error: Could not update the profile")

    logging.debug("update_profile: Succesful (%s)" % (username))

    if user:
        flash("Waiting for authorization to update user %s profile" % username,)
        return render_template('profile.html', current_user=user)


##### create a new post
### in[POST]: content, type
### creates new post for user
### redirects to home
@app.route('/create_post', methods=["GET", "POST"])
def create_post():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    safe = model.check_location(username)
    if request.method == 'GET':
        return render_template('create_post.html', current_user=user, safe=safe)

    new_content = request.form['content']
    type = request.form['type']

    logging.debug("create_post: Trying (%s, %s, %s)" % (username, new_content, type))

    if not new_content:
        flash("You need to introduce some content.", 'error')
        if type == "Secret" and not safe:
            return error("User is not in safe location")
        return render_template('create_post.html', current_user=user, safe=safe)

    try:
        if type == "Secret" and not safe:
            return error("User is not in safe location")
        new_post = model.new_post(username, new_content, type)
    except Exception as e:
        logging.debug("create_post: Found exception(%s)" % e)
        return error("Error: Could not create the post")

    if new_post:
        flash("Succesfully created new post",)
        logging.debug("create_post: Succesful (%s)" % (username))
    else:
        flash("Could not create new post",)

    return redirect(url_for('home'))


##### edit an existing post
### in[GET]: post_id
### shows current content of post with given id
### in[POST]: content, type, id
### edits post with given id. redirects to home
@app.route('/edit_post', methods=["GET", "POST"])
def edit_post():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    safe = model.check_location(username)
    if request.method == 'GET':
        post_id = request.args.get('id')
        try:
            post = model.get_post(post_id)
            if not post.author == user.username:
                logging.debug("edit_post1: Found exception(User is not the author of the post)")
                return error("User is not the author of the post")
            if post.type == "Secret" and not safe:
                return error("User is not in safe location")
        except Exception as e:
            logging.debug("edit_post1: Found exception(%s)" % e)
            return error("Error: Could not load the post")
        return render_template('edit_post.html', current_user=user, post=post, safe=safe)

    new_content = request.form['content']
    new_type = request.form['type']
    post_id = request.form['id']

    logging.debug("edit_post: Trying (%s, %s)" % (new_content, new_type))

    if not new_content:
        flash("You need to introduce some content.", 'error')
        if (post.type == "Secret" or new_type == "Secret") and not safe:
            return error("User is not in safe location")
        return render_template('edit_post.html', current_user=user, post=post, safe=safe)

    try:
        post = model.get_post(post_id)
        if not post.author == user.username:
            logging.debug("edit_post1: Found exception(User is not the author of the post)")
            return error("User is not the author of the post")
        if post.type == "Secret" and not safe:
            return error("User is not in safe location")
        new_post = model.edit_post(post_id, new_content, new_type)
    except Exception as e:
        logging.debug("edit_post2: Found exception(%s)" % e)
        return error("Error: Could not edit the post")

    if new_post:
        flash("Succesfully edited post",)
        logging.debug("edit_post: Succesful (%s)" % (username))
    else:
        flash("Could not edit post",)

    return redirect(url_for('home'))


##### request a new friendship
### in[POST]: username
### adds a new friendship request
### redirects to home
@app.route('/request_friend', methods=["GET", "POST"])
def request_friend():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    if request.method == 'GET':
        return render_template('request_friend.html', current_user=user)

    new_friend = request.form['username']
    logging.debug("request_friend: Trying (%s, %s)" % (username, new_friend))

    ### missing handling exception
    if not new_friend or not model.get_user(new_friend) or new_friend == username:
        flash("Introduce an existing username different from yours.", 'error')
        return render_template('request_friend.html', current_user=user)

    ### missing handling exception
    if new_friend in model.get_friends_aux(username) or model.is_request_pending(new_friend, username):
        flash("%s is already your friend, or a request from him is pending." % new_friend, 'error')
        return render_template('request_friend.html', current_user=user)

    try:
        new_request = model.new_friend_request(username, new_friend)
    except Exception as e:
        logging.debug("request_friend: Found exception(%s)" % e)
        return error("Error: Could not request friend")


    if new_request:
        flash("Succesfully created friend request to %s" % new_friend,)
        logging.debug("request_friend: Succesful (%s)" % (username))
    else:
        flash("Could not create friend request to %s" % new_friend,)

    return redirect(url_for('home'))


##### accept a friendship request
### in[POST]: username
### accepts the friendship request
### redirects to home
@app.route('/pending_requests', methods=["GET", "POST"])
def pending_requests():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    logging.debug("pending_requests: (%s)" % (user))

    try:
        friends_pending = model.get_pending_requests(username)
    except Exception as e:
        logging.debug("pending_requests1: Found exception(%s)" % e)
        return error("Error: Could not load pending friend requests")

    if request.method == 'GET':
        return render_template('pending_requests.html', current_user=user, friends_pending=friends_pending)

    accept_friend = request.form['username']

    if not accept_friend or not model.is_request_pending(accept_friend, username):
        flash("Introduce an existing friend request.", 'error')
        return render_template('pending_requests.html', current_user=user, friends_pending=friends_pending)

    try:
        new_friend = model.accept_friend_request(username, accept_friend)
    except Exception as e:
        logging.debug("pending_requests1: Found exception(%s)" % e)
        return error("Error: Could not accept friend request")

    logging.debug("pending_requests: Accepted %s:%s" % (username, accept_friend))

    if new_friend:
        flash("Succesfully accepted friend request of %s" % accept_friend,)
    else:
        flash("Could not accept friend request from %s" % accept_friend,)

    return redirect(url_for('home'))


##### show user's friends
### in[GET]: search_query
### searchs user's friends that match the search query
@app.route('/friends', methods=["GET"])
def friends():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    logging.debug("friends: current_user: %s" % (user))

    search_query = request.args.get('search', default = "")

    try:
        friends = model.get_friends(username, search_query)
    except Exception as e:
        logging.debug("friends: Found exception(%s)" % e)
        return error("Error: Could not load friends")

    return render_template('friends.html', current_user=user, friends=friends)

##### get a user's authorizations
### in[GET]: username
### sends the page with the users authorizations
### redirects to register otherwise
@app.route('/authorizations', methods=['GET'])
@csrf.exempt
def authorizations():
    username = None
    user = None
    if 'username' in session:
        username = session['username']
        user = model.get_user(username)

    logging.debug("authorizations: current_user: %s" % (user))

    try:
        authorizations = model.get_authorizations(username)
    except Exception as e:
        logging.debug("authorizations: Found exception(%s)" % e)
        return error("Error: Could not load authorizations")
    return render_template('authorizations.html', current_user=user, authorizations=authorizations)


##### receive an authorization confirmation
### in[POST]: username, hash, resp, signature
### authorizes or rejects an update
@app.route('/authorize', methods=['POST'])
@csrf.exempt
def authorize():
    body = request.get_json()
    if not body:
        raise BadRequest("Missing JSON body")
    expected = ["hash", "resp", "signature", "username"]
    real = sorted(list(body.keys()))
    if expected != real:
        raise BadRequest("Wrong JSON fields")
    username = body["username"]
    update_hash = body["hash"]
    resp = body["resp"]
    signature = body["signature"]

    # Verify signature
    to_hash = (username + resp + update_hash).encode()
    try:
        model.verify_auth_signature(base64.b64decode(signature), to_hash)
    except InvalidSignature:
        raise BadRequest("Invalid signature of request")

    authorization = model.get_authorization(username, update_hash)
    if not authorization:
        logging.debug(f"received authorization for unkown authorization request: {username}, {update_hash}")
        raise BadRequest("Unknown authorization request")

    # verify response
    if resp == "OK":
        success = model.authorize(authorization)
    elif resp == "NO":
        success = model.delete_authorization(authorization)
    else:
        raise BadRequest("Invalid response for authorization")
    if success:
        return Response("", status=200)
    else:
        return Response("", status=500)
