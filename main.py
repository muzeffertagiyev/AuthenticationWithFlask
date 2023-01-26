from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# With help of this section our login code work
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



##CREATE TABLE IN DB
with app.app_context():
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(1000))
    #Line below only required once, when creating DB. 
    # db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():

    if request.method == 'POST':

        if User.query.filter_by(email=request.form.get('email')).first():
            flash('You have already signed up with that email.Log in instead')
            return redirect(url_for('login'))   

        hashed_and_salted_password = generate_password_hash(
            password=request.form.get('password'),
            method="pbkdf2:sha256",
            salt_length=8
        )

        new_user = User(
            email=request.form.get('email'),
            name = request.form.get('name'),
            password = hashed_and_salted_password
        )
        
        
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('secrets'))

    return render_template("register.html")


@app.route('/login', methods=['POST',"GET"])
def login():

    if request.method == 'POST':
        user_email = request.form.get('email')
        entered_password = request.form.get('password')
        user = User.query.filter_by(email=user_email).first()
        
        if not user :
            flash('The email does not exist.Please try again')
            return redirect(url_for('login'))
        
        elif not check_password_hash(pwhash=user.password, password=entered_password):
            flash('Password is incorrect.Please try again')
            return redirect(url_for('login'))
            
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    # username = User.query.order_by(User.id).first().name
    username = current_user.name
    return render_template("secrets.html", name=username)


@app.route('/logout')
def logout():
    logout_user()
    flash('You logged out.You can login again')
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    filename = "files/cheat_sheet.pdf"
    return send_from_directory('static', filename)


if __name__ == "__main__":
    app.run(debug=True)
