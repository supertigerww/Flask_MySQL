from flask import Flask, request, redirect, render_template, session, flash
from datetime import datetime
from mysqlconnection import MySQLConnector
import re
import md5
emailRegex = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
passwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')
app = Flask(__name__)
mysql = MySQLConnector(app,'dojowall')
app.secret_key="laohu"

def validate():
    errors = 0
    #Check first name
    if request.form['firstName'] == '':
        flash('Name cannot be blank', 'firstNameError')
        errors += 1
        pass
    elif any(char.isdigit() for char in request.form['firstName']) == True:
        flash('Name cannot have numbers', 'firstNameError')
        errors += 1
        pass
    else:
        session['firstName'] = request.form['firstName']

    #Check last name
    if request.form['lastName'] == '':
        flash('Name cannot be blank', 'lastNameError')
        errors += 1
        pass
    elif any(char.isdigit() for char in request.form['lastName']) == True:
        flash('Name cannot have numbers', 'lastNameError')
        errors += 1
        pass
    else:
        session['lastName'] = request.form['lastName']

    #Check email
    if request.form['email'] == '':
        flash('Email cannot be blank', 'emailError')
        errors += 1
        pass
    elif not emailRegex.match(request.form['email']):
        flash('Invalid email address', 'emailError')
        errors += 1
        pass
    else:
        session['email'] = request.form['email']

    #Check password
    if request.form['password'] == '':
        flash('Password cannot be blank', 'passwordError')
        errors += 1
        pass
    elif len(request.form['password']) < 8:
        flash('Password must be greater than 8 characters', 'passwordError')
        errors += 1
        pass
    elif not passwordRegex.match(request.form['password']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'passwordError')
    else:
        session['password'] = request.form['password']

    #Check confirmation password
    if request.form['confirmPassword'] == '':
        flash('Please confirm password', 'confirmPasswordError')
        errors += 1
        pass
    elif request.form['confirmPassword'] != request.form['password']:
        flash('Passwords do not match', 'confirmPasswordError')
        errors += 1
    else:
        session['confirmPassword'] = request.form['confirmPassword']


    #See if there are any errors
    if errors > 0:
        return False
    else:
        return True

def validateLogin():
    errors = 0
     #Check email
    if request.form['loginemail'] == '':
        flash('Email cannot be blank', 'loginemailError')
        errors += 1
        pass
    elif not emailRegex.match(request.form['loginemail']):
        flash('Invalid email address', 'loginemailError')
        errors += 1
        pass
    else:
        session['loginemail'] = request.form['loginemail']

    #Check password
    if request.form['loginpassword'] == '':
        flash('Password cannot be blank', 'loginpasswordError')
        errors += 1
        pass
    elif len(request.form['loginpassword']) < 8:
        flash('Password must be greater than 8 characters', 'loginpasswordError')
        errors += 1
        pass
    elif not passwordRegex.match(request.form['loginpassword']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'loginpasswordError')
        errors += 1
        pass
    else:
        session['loginpassword'] = request.form['loginpassword']

        #See if there are any errors
    if errors > 0:
        return False
    else:
        return True
@app.route('/')
def index():
    if 'firstName' not in session:
        session['firstName'] = ''
    if 'lastName' not in session:
        session['lastName'] = ''
    if 'email' not in session:
        session['email'] = ''
    if 'password' not in session:
        session['password'] = ''
    if 'confirmPassword' not in session:
        session['confirmPassword'] = ''
    if 'loginemail' not in session:
        session['loginemail'] = ''
    if 'loginpassword' not in session:
        session['loginpassword'] = ''
    
    return render_template('index.html')
@app.route('/process',methods=['POST'])
def create():
    if validate()== False:
        return redirect('/')
    else:
        encryptedPassword = md5.new(request.form['password']).hexdigest()
        query="INSERT INTO users (id, first_name,last_name, email, password)VALUES(NULL, :first_name, :last_name, :email, :password)"
        data={
            'first_name':session['firstName'],
            'last_name':session['lastName'],
            'email':session['email'],
            'password':encryptedPassword
        }
        mysql.query_db(query,data)
    return redirect ('/success')
@app.route('/login',methods=['POST'])
def login():
    # Makes sure email and password were input
    if request.form['loginemail'] and request.form['loginpassword']:
        query = "SELECT * FROM users WHERE email=:email"
        data = {
            'email': request.form['loginemail']
        }
        # checks of user matches in db
        if len(mysql.query_db(query, data)) > 0:
            user = mysql.query_db(query, data)[0]
            print("user: {}".format(user))
            if md5.new(request.form['loginpassword']).hexdigest() == user['password']:
                # Adds user to session
                session['user'] = user
                return redirect('/success')
    flash("Incorrect username or password","loginError")
    return redirect('/')

        
@app.route('/success')
def show():
    if 'user' in session:
        query = "SELECT first_name, last_name, message, DATE_FORMAT(messages.created_at, '%M %D %Y %H:%i') AS created_at, messages.id, users_id FROM messages JOIN users ON messages.users_id = users.id ORDER BY messages.created_at DESC"
        message_list=mysql.query_db(query)
        query = "SELECT first_name, last_name, comment, DATE_FORMAT(comments.created_at, '%M %D %Y %H:%i') AS created_at, messages_id FROM comments JOIN users ON comments.users_id = users.id ORDER BY comments.created_at"
        comment_list = mysql.query_db(query)
        return render_template('success.html', message_list=message_list, user=session['user'],comment_list=comment_list)
    else:
        flash("Please login first")
        return redirect('/')
@app.route('/message',methods=['POST'])
def addmessage():
    query="INSERT INTO messages (message, users_id)VALUES(:message, :users_id)"
    data={
        'message':request.form['message'],
        'users_id':session['user']['id']
    }
    mysql.query_db(query,data)
    return redirect('/success')
@app.route('/success/comment/<message_id>', methods=['POST'])
def comment(message_id):
    query="INSERT INTO comments(comment,users_id,messages_id )VALUES(:comment,:users_id, :messages_id)"
    data={
        'comment':request.form['comment'],
        'users_id':session['user']['id'],
        'messages_id':message_id
    }
    mysql.query_db(query,data)
    return redirect('/success')
@app.route('/logout',methods=['POST'])
def logout():
    session.pop('user',None)
    return redirect('/')
    


app.run(debug=True)