from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from databases import Mongo
import re
from hashlib import sha256
import encryption

app = Flask(__name__)

# Config
app.config['SECRET_KEY'] = 'mysecretkey'


# Database
MONGO_URI = "mongodb://localhost:27017"
client = Mongo(MONGO_URI)

# Password strength checker
def password_strength(password):
    score = 0
    # Check length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    # Check for presence of uppercase, lowercase, digits, and special characters
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*()-+=]", password):
        score += 1
    # Determine password difficulty
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"

    
# Routes
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = client.get_user(session['user_id'])
    data = client.get_data(session['user_id'])
    return render_template('home.html', user=user, data=data)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form['email']
        password = sha256(request.form['password'].encode()).hexdigest() # Hashing the password
        db_user = client.get_user(email)
        if db_user and db_user['password'] == password:
            session['user_id'] = email
            return redirect('/')
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect('/')
    
    if request.method == 'POST':
        email = request.form['email']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect('/signup')
        
        elif len(password) < 8 or len(password) > 26:
            flash('Password must be at least 8 characters long and maximum 26 characters', 'danger')
            return redirect('/signup')
        
        elif any(char.isdigit() for char in password) is False:
            flash('Password must contain at least one number', 'danger')
            return redirect('/signup')
        
        elif any(char.isupper() for char in password) is False:
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect('/signup')
        
        elif any(char.islower() for char in password) is False:
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect('/signup')
        
        elif any(char.isspace() for char in password) is True:
            flash('Password must not contain any spaces', 'danger')
            return redirect('/signup')
        
        if client.get_user(email):
            flash('Email already exists', 'danger')
            return redirect('/signup')
        else:
            # Generating Privete Key & Public Key
            public_key, private_key = encryption.encode_key(password)
            # Hashing the password
            password_hash = sha256(password.encode()).hexdigest()
            client.add_user(password_hash, email, public_key, private_key)
            session['user_id'] = email
            return redirect('/')
    return render_template('signup.html')

# Add
@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        website = request.form['website']
        email = request.form['email']
        password = request.form['password']
        owner_id = session['user_id']
        
        user_data = client.get_user(session['user_id'])
        # Validation
        data = client.get_data(owner_id)
        if data:
            for d in data:
                if d['website'] == website and d['email'] == email:
                    flash('Email already exists', 'danger')
                    return redirect(url_for('add'))
                
        encrypted_password = encryption.encode_data(password, user_data['public_key'])
        difficulty = password_strength(password)
        client.add_data(website, email, encrypted_password, owner_id, difficulty)
        flash('Password added successfully', 'success')
        return redirect('/')
    return render_template('add.html')

# Edit
@app.route('/edit', methods=['GET', 'POST'])
def tedit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        id = request.form['id']
        password = request.form['password']
        user_data = client.get_user(session['user_id'])
        if sha256(password.encode()).hexdigest() != user_data['password']:
            flash('Invalid password', 'danger')
            return redirect(f'/decrypt/{id}')
        data = client.get_by_id(id)
        decoded_key = encryption.decode_key(user_data['private_key'], password)
        data['password'] = encryption.decode_data(data['password'], decoded_key)
        flash('Password updated successfully', 'success')
    return render_template('edit.html', data=data)

# Decrypt
@app.route('/decrypt/<string:doc_id>', methods=['GET', 'POST'])
def decrypt(doc_id):
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'})
    if request.method == 'POST':
        id = doc_id
        password = request.form['password']
        user_data = client.get_user(session['user_id'])
        if sha256(password.encode()).hexdigest() != user_data['password']:
            return jsonify({'message': 'Invalid password'})
        return redirect(url_for('edit',id=id))
    return render_template('decrypt.html', id=doc_id)

# Delete
@app.route('/delete', methods=['POST'])
def delete():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        id = request.form['id']
        client.delete_data(id)
        flash('Password deleted successfully', 'success')
        return redirect('/')

# Settings
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == 'POST':
        password = request.form['password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_new_password']

        user_data = client.get_user(session['user_id'])

        if user_data['password'] != password:
            flash('Invalid password', 'danger')
            return redirect('/settings')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect('/settings')
        
        elif len(new_password) < 8 or len(new_password) > 26:
            flash('Password must be at least 8 characters long and maximum 26 characters', 'danger')
            return redirect('/settings')
        
        elif any(char.isdigit() for char in new_password) is False:
            flash('Password must contain at least one number', 'danger')
            return redirect('/settings')
        
        elif any(char.isupper() for char in new_password) is False:
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect('/settings')
        
        elif any(char.islower() for char in new_password) is False:
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect('/settings')
        
        elif any(char.isspace() for char in new_password) is True:
            flash('Password must not contain any spaces', 'danger')
            return redirect('/settings')
        
        elif new_password == password:
            flash('New password cannot be the same as the old password', 'danger')
            return redirect('/settings')
        else:
            user_data['password'] = sha256(new_password.encode()).hexdigest() # Hashing the new_password
            client.update_user(session['user_id'], user_data)
            flash('Password updated successfully', 'success')
            return redirect('/')
    return render_template('settings.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)
