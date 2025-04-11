from flask import Flask, render_template, redirect, url_for, session, flash, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
import MySQLdb
import MySQLdb.cursors
import uuid
import json
import jwt as PyJWT
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)

# Configure MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'admin',
    'db': 'swabhoomi',
    'cursorclass': MySQLdb.cursors.DictCursor
}

app.secret_key = 'your_secret_key_here'

def get_db():
    """Get database connection"""
    try:
        connection = MySQLdb.connect(**DB_CONFIG)
        return connection
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Initialize database
def init_db():
    try:
        # First connect without database
        conn = MySQLdb.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()
        
        # Create database
        cursor.execute("CREATE DATABASE IF NOT EXISTS swabhoomi")
        cursor.execute("USE swabhoomi")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                did VARCHAR(255) UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create addresses table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS addresses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                address_type VARCHAR(50) NOT NULL,
                street_address TEXT NOT NULL,
                city VARCHAR(100) NOT NULL,
                state VARCHAR(100) NOT NULL,
                postal_code VARCHAR(20) NOT NULL,
                country VARCHAR(100) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create properties table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS properties (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                location VARCHAR(255) NOT NULL,
                area DECIMAL(10,2) NOT NULL,
                status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create verifiable_credentials table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS verifiable_credentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                type VARCHAR(100) NOT NULL,
                credential_data JSON NOT NULL,
                status ENUM('active', 'revoked') DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully!")
        return True
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False

# Initialize database on startup
init_db()

class RegisterForm(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    street = TextAreaField("Street Address", validators=[DataRequired()])
    city = StringField("City", validators=[DataRequired()])
    state = StringField("State", validators=[DataRequired()])
    country = StringField("Country", validators=[DataRequired()])
    pincode = StringField("Pincode", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        try:
            conn = get_db()
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
                user = cursor.fetchone()
                cursor.close()
                conn.close()
                if user:
                    raise ValidationError('Email already registered. Please choose a different one.')
        except Exception as e:
            print(f"Database error in validate_email: {e}")
            raise ValidationError('Unable to validate email. Please try again.')

class LoginForm(FlaskForm):
    email=StringField("Email", validators=[DataRequired(), Email()])
    password=PasswordField("Password", validators=[DataRequired()])
    submit=SubmitField("Login")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            conn = get_db()
            if not conn:
                flash('Database connection error. Please try again later.', 'error')
                return render_template('register.html', form=form)

            cursor = conn.cursor()

            # Check if passwords match
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match.', 'error')
                return render_template('register.html', form=form)

            first_name = form.first_name.data
            last_name = form.last_name.data
            email = form.email.data
            password = form.password.data
            street = form.street.data
            city = form.city.data
            state = form.state.data
            country = form.country.data
            pincode = form.pincode.data

            # Check if email already exists
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            if existing_user:
                cursor.close()
                conn.close()
                flash('Email already registered. Please choose a different one.', 'error')
                return render_template('register.html', form=form)

            # Hash password
            hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Store user data
            cursor.execute("""
                INSERT INTO users (name, email, password) 
                VALUES (%s, %s, %s)
            """, (f"{first_name} {last_name}", email, hash_password))
            conn.commit()
            user_id = cursor.lastrowid

            # Store address data
            cursor.execute("""
                INSERT INTO addresses (user_id, address_type, street_address, city, state, postal_code, country) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, 'PRIMARY', street, city, state, pincode, country))
            conn.commit()
            
            cursor.close()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect('/login')

        except Exception as e:
            print(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html', form=form)
    
    return render_template('register.html', form=form)

def generate_did():
    """Generate a unique DID for a user"""
    # Generate a unique identifier
    unique_id = str(uuid.uuid4())
    # Create a DID in the format: did:swabhoomi:unique_id
    did = f"did:swabhoomi:{unique_id}"
    return did

def generate_verifiable_credential(user_data):
    """Generate a verifiable credential for the user"""
    # Create a credential ID
    credential_id = f"vc:{uuid.uuid4()}"
    
    # Create the credential
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/identity/v1"
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", "IdentityCredential"],
        "issuer": "did:swabhoomi:issuer",
        "issuanceDate": datetime.utcnow().isoformat(),
        "credentialSubject": {
            "id": user_data['did'],
            "type": "Person",
            "givenName": user_data['first_name'],
            "familyName": user_data['last_name'],
            "email": user_data['email']
        }
    }
    
    # Sign the credential (in a real implementation, this would use proper cryptographic signing)
    signed_credential = PyJWT.encode(
        credential,
        app.secret_key,
        algorithm='HS256'
    )
    
    return signed_credential

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        connection = get_db()
        if connection:
            cursor = connection.cursor()
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session['user_id'] = user['id']
                session['email'] = user['email']
                
                # Generate DID if user doesn't have one
                if not user['did']:
                    did = generate_did()
                    connection = get_db()
                    if connection:
                        cursor = connection.cursor()
                        cursor.execute('UPDATE users SET did = %s WHERE id = %s', (did, user['id']))
                        connection.commit()
                        cursor.close()
                        connection.close()
                        
                        # Generate verifiable credential
                        user_data = {
                            'did': did,
                            'first_name': user['first_name'],
                            'last_name': user['last_name'],
                            'email': user['email']
                        }
                        vc = generate_verifiable_credential(user_data)
                        
                        # Store the credential
                        connection = get_db()
                        if connection:
                            cursor = connection.cursor()
                            cursor.execute(
                                'INSERT INTO verifiable_credentials (user_id, credential_type, credential_data) VALUES (%s, %s, %s)',
                                (user['id'], 'identity', vc)
                            )
                            connection.commit()
                            cursor.close()
                            connection.close()
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')

    try:
        conn = get_db()
        if not conn:
            flash('Database connection error. Please try again later.')
            return redirect('/login')

        user_id = session.get('user_id')
        cursor = conn.cursor()
        
        # Get user data
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            session.pop('user_id', None)
            flash('User not found. Please login again.')
            return redirect('/login')
        
        # Get property counts
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
            FROM properties 
            WHERE user_id = %s
        """, (user_id,))
        counts = cursor.fetchone()
        
        # Get recent properties
        cursor.execute("""
            SELECT * FROM properties 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT 5
        """, (user_id,))
        recent_properties = cursor.fetchall()
        
        # Get verifiable credentials
        cursor.execute("""
            SELECT * FROM verifiable_credentials 
            WHERE user_id = %s AND status = 'active'
        """, (user_id,))
        verifiable_credentials = cursor.fetchall()
        
        cursor.close()
        conn.close()

        return render_template('dashboard.html',
            current_user=user,
            land_count=counts['total'] or 0,
            verified_count=counts['verified'] or 0,
            pending_count=counts['pending'] or 0,
            issues_count=counts['rejected'] or 0,
            recent_properties=recent_properties,
            verifiable_credentials=verifiable_credentials
        )
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash('An error occurred. Please try again.')
        return redirect('/login')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')

    try:
        conn = get_db()
        if not conn:
            flash('Database connection error. Please try again later.')
            return redirect('/login')

        user_id = session.get('user_id')
        
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.*, a.* 
            FROM users u 
            LEFT JOIN addresses a ON u.id = a.user_id 
            WHERE u.id=%s
        """, (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_data:
            return render_template('profile.html', user_data=user_data)
        
        session.pop('user_id', None)
        flash('User not found. Please login again.')
        return redirect('/login')
    except Exception as e:
        print(f"Profile error: {e}")
        flash('An error occurred. Please try again.')
        return redirect('/login')

@app.route('/digital-identity')
def digital_identity():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')
    return render_template('digital_identity.html')

@app.route('/land-registry')
def land_registry():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')
    return render_template('land_registry.html')

@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')
    return render_template('transactions.html')

@app.route('/documents')
def documents():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')
    return render_template('documents.html')

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash('Please login first.')
        return redirect('/login')
    return render_template('settings.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('You have been successfully logged out.', 'success')
    return redirect('/')  # Redirect to index page instead of login

@app.route('/test-db')
def test_db():
    try:
        conn = get_db()
        if not conn:
            return "Database connection failed"
        
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        
        # Get table structures
        table_info = {}
        for table in tables:
            table_name = table['Tables_in_swabhoomi']
            cursor.execute(f"DESCRIBE {table_name}")
            table_info[table_name] = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('test_db.html', tables=tables, table_info=table_info)
    except Exception as e:
        return f"Error: {str(e)}"

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)