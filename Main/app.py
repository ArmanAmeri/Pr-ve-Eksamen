# Importerer nødvendige biblioteker
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import bcrypt
from dotenv import load_dotenv

# Laster miljøvariabler fra .env fil
load_dotenv()

# Oppretter Flask-applikasjonen og konfigurerer den
app = Flask(__name__)
# Konfigurerer sikkerhetsinnstillinger og database-tilkobling
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialiserer database og innloggingshåndtering
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Definerer brukermodellen med all nødvendig informasjon
class User(UserMixin, db.Model):
    # Databasekolonner for brukerinformasjon
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    is_locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, username, email, password, is_admin=False):
        self.username = username
        self.email = email
        self.set_password(password)
        self.is_admin = is_admin

    # Metode for å sette passord med sikker hashing
    def set_password(self, password):
        # Konverterer passord til bytes hvis det er en streng
        if isinstance(password, str):
            password = password.encode('utf-8')
        # Genererer unik salt og hasher passordet
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)
        # Lagrer hashen som en streng i databasen
        self.password_hash = hashed.decode('utf-8')

    # Metode for å sjekke om et passord er korrekt
    def check_password(self, password):
        # Konverterer passord til bytes hvis det er en streng
        if isinstance(password, str):
            password = password.encode('utf-8')
        # Konverterer lagret hash tilbake til bytes
        stored_hash = self.password_hash.encode('utf-8')
        return bcrypt.checkpw(password, stored_hash)

# Hjelpefunksjon for å laste bruker ved innlogging
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Hovedside
@app.route('/')
def index():
    return render_template('index.html')

# Innloggingsside med sikkerhetsfunksjoner
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Sjekker om kontoen er låst
        if user and user.is_locked:
            if datetime.utcnow() - user.last_login_attempt > timedelta(minutes=15):
                user.is_locked = False
                user.failed_login_attempts = 0
                db.session.commit()
            else:
                flash('Account is locked. Please try again later.', 'error')
                return redirect(url_for('login'))

        # Verifiserer passord og logger inn bruker
        if user and user.check_password(password):
            login_user(user)
            user.failed_login_attempts = 0
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            # Håndterer feil innlogging og låser konto etter 5 forsøk
            if user:
                user.failed_login_attempts += 1
                user.last_login_attempt = datetime.utcnow()
                if user.failed_login_attempts >= 5:
                    user.is_locked = True
                db.session.commit()
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Kontrollpanel for innloggede brukere
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Utloggingsfunksjon
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Registreringsside med validering
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validerer input
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        # Sjekker om brukernavn eller e-post allerede eksisterer
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('signup'))

        # Oppretter ny bruker med sikker passordhashing
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Legg til en admin-bruker hvis den ikke eksisterer
def create_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            password='admin123',  # Endre dette i produksjon!
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# Admin-beskyttet rute
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Du har ikke tilgang til admin-dashbordet.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.is_admin and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Ugyldig admin-innlogging.', 'error')
    
    return render_template('admin/login.html')

# Admin-beskyttet rute for å slette brukerkontoer
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Du har ikke tilgang til denne handlingen.', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    
    if user:
        # Sletter brukeren fra databasen
        db.session.delete(user)
        db.session.commit()
        flash('Brukeren har blitt slettet.', 'success')
    else:
        flash('Brukeren ble ikke funnet.', 'error')
    
    return redirect(url_for('admin_dashboard'))


# Starter applikasjonen og oppretter databasetabeller
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        #create_admin()
    app.run(debug=True, ssl_context='adhoc')
