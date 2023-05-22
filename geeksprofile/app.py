# Store this code in 'app.py' file
from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash
import pymysql
from flask_cors import CORS
import re
import jwt, os
from datetime import timedelta, datetime
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base



Base = declarative_base()

# If root user has a non-blank password, add password after 'root:'
engine = create_engine('mysql+pymysql://root:@localhost/geekprofile')

class User(Base):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    organisation = Column(String(255), nullable=False)
    address = Column(String(255), nullable=False)
    city = Column(String(50), nullable=False)
    state = Column(String(50), nullable=False)
    country = Column(String(50), nullable=False)
    postalcode = Column(String(50), nullable=False)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'upload_folder'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 # set max file size to 2MB

 # CORS(app)
cors = CORS(app, resources={r"/*": {"origins": "*"}})
 
app.secret_key = 'happykey'
app.permanent_session_lifetime = timedelta(minutes=10)


# create a session factory
Session = sessionmaker(bind=engine)

# create a new session
session = Session()



# If root user has a non-blank password, replace the empty string in 'password = ""' with the actual password
conn = pymysql.connect(
        host='localhost',
        user='root', 
        password = "",
        db='geekprofile',
		cursorclass=pymysql.cursors.DictCursor
        )
cur = conn.cursor()







@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html') , 404


@app.errorhandler(400)
def bad_request():
    return render_template('400.html') , 400

@app.errorhandler(401)
def user_not_authorized():
    return render_template('401.html') , 401
 

def authenticate_user(username, password):
    try:
        print(f"SELECT * FROM accounts WHERE username = '{username}'")
        cur.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cur.fetchone()
        #print(account)
        
        
        if account and check_password_hash(account['password'],password):
            found_account = User(
                id = account['id'],
                username=account['username'],
                password=account['password'],
                email=account['email'],
                organisation=account['organisation'] ,
                address=account['address'],
                city=account['city'],
                state=account['state'],
                country=account['country'],
                postalcode=account['postalcode']
            )
            return found_account
        else:
            return None
    except Exception as e:
        print(e)
        return None




@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        
        username = request.form['username']
        password = request.form['password']
        
        account = authenticate_user(username, password)

        if account:
            # Generate JWT token
            token_payload = {
                'user_id': account.id,
                'username': account.username,
                'password_hash': account.password,
                'organization' : account.organisation,
                'email' : account.email,
                'address' : account.address,
                'city' : account.city,
                'postalcode' : account.postalcode,
                'country' : account.country,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }
            token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')
            #Store token in a secure cookie
            response = make_response(render_template('index.html',msg=msg))
            response.set_cookie('token', token)
            return response
        else:
            msg = 'Incorrect username / password !'
    return render_template('login.html', msg = msg)
 
@app.route('/logout')
def logout():
   response = make_response(redirect(url_for('login')))
   response.delete_cookie('token')
   return response
 
@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form:
        
        
        user = User(
            username=request.form['username'],
            password=generate_password_hash(request.form['password']),
            email=request.form['email'],
            organisation=request.form['organisation'] ,
            address=request.form['address'],
            city=request.form['city'],
            state=request.form['state'],
            country=request.form['country']   ,
            postalcode=request.form['postalcode']
        )
        
        cur.execute('SELECT * FROM accounts WHERE username = % s', (user.username, ))
        account = cur.fetchone()
        print(account)
        conn.commit()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', user.email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', user.username):
            msg = 'name must contain only characters and numbers !'
        else:
            session.add(user)
            session.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)
 
 
@app.route("/index")
def index():
    token = request.cookies.get('token')
    if (token):
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            user_id = payload['user_id']
            #check if user's in the database
            account = session.query(User).filter_by(id=user_id).first()
            if account:
                return render_template("index.html")
        except jwt.ExpiredSignatureError:
            pass #Handle Expired Token
        except (jwt.InvalidTokenError,KeyError):
            pass # handle invalid token or missing user_id in paylod
    return redirect(url_for('login'))
 
@app.route("/display")
def display():
    token = request.cookies.get('token')
    if (token):
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            user_id = payload['user_id']
            #check if user's in the database
            account = session.query(User).filter_by(id=user_id).first()
            if account:
                return render_template("display.html", account=account)
        except jwt.ExpiredSignatureError:
            pass #Handle Expired Token
        except (jwt.InvalidTokenError,KeyError):
            pass # handle invalid token or missing user_id in paylod
    return redirect(url_for('login'))


def allowed_file(filename):
    """
    Returns True if the filename has an allowed extension, False otherwise.
    """
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/public', methods=['GET'])
def public():
    accounts = session.query(User).all()
    organizations = [account.organisation for account in accounts]
    return render_template('public.html', organizations=organizations)

@app.route("/upload") 
def upload():
    """
    Loads the upload.html page
    """
    token = request.cookies.get('token')
    if (token):
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            user_id = payload['user_id']
            # check if user is in the database
            account = session.query(User).filter_by(id=user_id).first()
            if account:
                return render_template("upload.html", account=account)
        except jwt.ExpiredSignatureError:
            pass  # Handle Expired Token
        except (jwt.InvalidTokenError, KeyError):
            pass  # handle invalid token or missing user_id in payload
    return redirect(url_for('login'))


@app.route('/upload-file', methods=['POST'])
def upload_file():
    """
    Handles the file upload
    """
    token = request.cookies.get('token')
    if (token):
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            user_id = payload['user_id']
            # check if user is in the database
            account = session.query(User).filter_by(id=user_id).first()
            if account:
                # check if the post request has the file part
                if 'file' not in request.files:
                    flash('No file part')
                    return redirect(request.url)
                file = request.files['file']
                # if user does not select file, browser also
                # submit an empty part without filename
                if file.filename == '':
                    flash('No selected file')
                    return redirect(request.url)
                if file and allowed_file(file.filename):
                    #check the size of the file to make sure it meets constraints
                    file_size = request.content_length
                    max_file_size = app.config['MAX_CONTENT_LENGTH']
                    if file_size > max_file_size:
                        flash("FILE SIZE TOO LARGE")
                        return redirect(request.url)
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    return redirect(url_for('upload'))
                else:
                    return bad_request()

        except jwt.ExpiredSignatureError:
            pass  # Handle Expired Token
        except (jwt.InvalidTokenError, KeyError):
            pass  # handle invalid token or missing user_id in payload
    return redirect(url_for('login'))


@app.route("/admin")
def admin():
    token = request.cookies.get('token')
    if (token):
        try:
            payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            username = payload['username']
            account = session.query(User).filter_by(username=username).first()
            #is this person the administrator?
            if (account and username=='admin'):
                return render_template("admin.html", account=account)
            else:
                #if the username's not admin then return 401 error
                return user_not_authorized()
        except jwt.ExpiredSignatureError:
            pass #Handle Expired Token
        except (jwt.InvalidTokenError,KeyError):
            pass # handle invalid token or missing user_id in paylod
    return redirect(url_for('login'))


@app.route("/update", methods =['GET', 'POST'])
def update():
    msg = ''
    token = request.cookies.get('token')
    payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
    if (token):
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organisation' in request.form:
            username = request.form['username']
            password = generate_password_hash(request.form['password'])
            email = request.form['email']
            organisation = request.form['organisation'] 
            address = request.form['address']
            city = request.form['city']
            state = request.form['state']
            country = request.form['country']   
            postalcode = request.form['postalcode']
            cur.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
            account = cur.fetchone()
            if account:
                msg = 'Account already exists !'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address !'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'name must contain only characters and numbers !'
            else:
                cur.execute('UPDATE accounts SET username =% s, password =% s, email =% s, organisation =% s, address =% s, city =% s, state =% s, country =% s, postalcode =% s WHERE id =% s', (username, password, email, organisation, address, city, state, country, postalcode, (payload['user_id'], ), ))
                conn.commit()
                msg = 'You have successfully updated !'
        elif request.method == 'POST':
            msg = 'Please fill out the form !'
        return render_template("update.html", msg = msg)
    return redirect(url_for('login'))

  

 
if __name__ == "__main__":
    app.run(host ="localhost", port = int("5000"))
