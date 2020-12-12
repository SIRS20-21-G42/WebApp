from flask import Flask
from flask_mysqldb import MySQL
from flask_qrcode import QRcode
from flask_wtf.csrf import CSRFProtect

import os
import sys
import time

from jinja2 import Environment

app = Flask(__name__)

app.config['SECRET_KEY']         = '\x83\xe1\xba%j\x0b\xe5Q\xdeiG\xde\\\xb1\x94\xe4\x0e\x1dk\x99\x1a\xda\xe8x'
app.config['MYSQL_HOST']         = os.environ["DB_HOST"]
app.config['MYSQL_USER']         = 'facefive'
app.config['MYSQL_PASSWORD']     = 'facefivepass'
app.config['MYSQL_DB']           = 'facefivedb'
app.config['photos_folder']      = './static/photos/'
app.config['default_photo']      = 'default-user.jpg'
app.config['MAX_CONTENT_LENGTH'] = 102400
app.config['IMAGE_EXTENSIONS']   = ('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff')

app.config['AUTH_SERVER']    = "https://authserver:5000"
app.config['AUTH_CERT_PATH'] = "auth/AUTH.cert"
app.config['CA_CERT_PATH']   = "auth/CA.cert"
app.config['MY_CERT_PATH']   = "auth/FaceFive.cert"
app.config['MY_PRIV_PATH']   = "auth/FaceFive.key"
app.config['MY_SECRET_KEY']  = "auth/FacefiveSecret.key"

app.config.update(SESSION_COOKIE_SAMESITE="Lax")

mysql = MySQL(app)
csrf = CSRFProtect(app)
qrcode = QRcode(app)

@app.context_processor
def inject():
    return {'photos_folder' : app.config['photos_folder']}

from model import *
from views import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True, ssl_context=(app.config["MY_CERT_PATH"], app.config["MY_PRIV_PATH"]))
