import os
import secrets

from flask import Flask, render_template, request, redirect, send_from_directory
from flask import current_app
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from config import mail_username, mail_password


app = Flask(__name__)


#ptapp.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgresql@localhost:5433/Flasksql'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'key'


app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = mail_username
app.config['MAIL_PASSWORD'] = mail_password


mail = Mail(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


Login_manager = LoginManager()
Login_manager.init_app(app)
Login_manager.login_view = "login"


def save_images(photo):
    hash_photo = secrets.token_urlsafe(10)
    _, file_extention = os.path.splitext(photo.filename)
    photo_name = hash_photo + file_extention
    file_path = os.path.join(current_app.root_path, 'static/images', photo_name)
    photo.save(file_path)
    return photo_name


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image1 = db.Column(db.String(120), default='image1.jpg')
    image2 = db.Column(db.String(120), default='image2.jpg')
    image3 = db.Column(db.String(120), default='image3.jpg')
    image4 = db.Column(db.String(120), default='image4.jpg')
    text = db.Column(db.String(100), nullable=False)
    isActive = db.Column(db.Boolean, default=True)


    def __repr__(self):
        return self.title


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username "})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")



@Login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/static/images/<filename>')
def display_image(filename):
    return send_from_directory("static", filename=filename)





@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('/dashboard')
    return render_template('login.html', form=form)





@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html', form=form)


@app.route('/dashboard/<int:id>/delete')
def itemdelete(id):
    item = Item.query.get_or_404(id)
    try:
        db.session.delete(item)
        db.session.commit()
        return redirect('/dashboard')
    except:
        return "Error"

    return render_template("dashboard.html", data=item)


@app.route('/', methods=['POST', 'GET'])
def index():
    items = Item.query.all()
    return render_template("index.html", data=items)


@app.route('/support', methods=['POST', 'GET'])
def support():
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        msg = Message(subject=f"Mail from {name}", body=f"Name: {name}\nE-Mail: {email}\n{message}",
                      sender=mail_username, recipients=['polskoydm@gmail.com,Jiliyahaifa@gmail.com'])
        mail.send(msg)
        return render_template('support.html', success=True)

    return render_template('support.html')



@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    items = Item.query.all()
    if request.method=="POST":
        title = request.form.get('title')
        price = request.form.get('price')
        text = request.form.get('text')
        photo1 = save_images(request.files.get('photo1'))
        photo2 = save_images(request.files.get('photo2'))
        photo3 = save_images(request.files.get('photo3'))
        photo4 = save_images(request.files.get('photo4'))

    try:
        item = Item(title=title, price=price, text=text, image1=photo1, image2=photo2, image3=photo3, image4=photo4)
        db.session.add(item)
        db.session.commit()
        return redirect('/dashboard')

    except: "Error"

    return render_template('dashboard.html', data=items)


@app.route('/product/<id>')
def product(id):
    item = Item.query.filter_by(id=id)
    return render_template('view-product.html', data=item)

if __name__ == "__main__":
    app.run(debug=True)
