# conda activate
# python app.py
from flask import Flask, render_template, url_for, redirect,request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, Length
from flask_bcrypt import Bcrypt
import pickle
import numpy as np


global second 
app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

app.app_context().push()
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
model = pickle.load(open('ml_Model.pickle','rb'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(50),unique = True)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[InputRequired(),Email(message="Invalid email"),Length(max=50)],render_kw={"placeholder": "Email"})
    submit = SubmitField('register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('login')


class Survey(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    education = db.Column(db.Integer)
    concentrate = db.Column(db.Boolean)
    anxiety = db.Column(db.Boolean)
    depression = db.Column(db.Boolean)
    overthinking = db.Column(db.Boolean)
    mood = db.Column(db.Boolean)
    panic = db.Column(db.Boolean)
    repetitive = db.Column(db.Boolean)
    lack = db.Column(db.Boolean)
    overthinking = db.Column(db.Boolean)
    age = db.Column(db.Integer)
    gender = db.Column(db.Boolean)


@app.route('/', methods=['GET', 'POST'])
def home():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template("index.html")
    return render_template('login.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    second = False
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template("index.html")
    return render_template('login.html', form=form)





@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    second = False
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password,email=form.email.data,)
        db.session.add(new_user)
        db.session.commit()
        return render_template("index.html")

    return render_template('register.html', form=form)

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/game')
def game():
    return render_template('game.html')


@app.route('/blogs')
def blogs():
    return render_template('blogs.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/predict1')
def predict1():
    return render_template('form.html',result="Complete the survey to predict the mental health")

@app.route('/predict',methods=["GET","POST"])
def predict():
    int_features = [int(x) for x in request.form.values()]
    final = [np.array(int_features)] # total 11 entry
    finalArray = final[0]
    print(len(finalArray))
    survey = Survey()
    for i in range(len(finalArray)):
        print(finalArray[i])
    survey.education = int(finalArray[0])
    survey.concentrate = finalArray[1]
    survey.anxiety = finalArray[2]
    survey.depression = finalArray[3]
    survey.overthinking = finalArray[4]
    survey.mood = finalArray[5]
    survey.panic = finalArray[6]
    survey.repetitive = finalArray[7]
    survey.lack = finalArray[8]
    survey.age = int(finalArray[9]) 
    survey.gender = finalArray[10]
    print(len(finalArray))
    db.session.add(survey)
    db.session.commit()
    prediction = model.predict(final)
    output = prediction
    if output == 1:
        return render_template('result.html')
    else:
        return render_template('form.html',result="You are in a good mental health")


if __name__ == "__main__":
    second = False
    app.run(debug=True)