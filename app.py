from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, DateField, PasswordField, BooleanField, SelectField, FloatField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, current_user, logout_user, login_required, login_user
from collections import defaultdict
from sqlalchemy import func

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "1111"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    date = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Expense('{self.title}', '{self.category}', '{self.amount}', '{self.date}')"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    expenses = db.relationship('Expense', backref='author', lazy=True)
    shared_stats = db.relationship('SharedStats', foreign_keys='SharedStats.owner_id', backref='owner', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class SharedStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_with_username = db.Column(db.String(20), nullable=False)  # Changed to username
    shared_with_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class ExpenseForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    category = StringField("Category", validators=[DataRequired()])
    amount = DecimalField("Amount", validators=[DataRequired()])
    date = DateField("Date", default=datetime.utcnow, validators=[DataRequired()])
    submit = SubmitField("Submit")

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class TimeRangeForm(FlaskForm):
    time_range = SelectField('Time Range', choices=[('last_month', 'Last Month'), ('last_year', 'Last Year')], validators=[DataRequired()])
    submit = SubmitField('Show Statistics')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class SearchForm(FlaskForm):
    search_term = StringField('Search Expense by Title', validators=[DataRequired()])
    submit = SubmitField('Search')

class ShareStatsForm(FlaskForm):
    shared_with_username = StringField('Username to share with', validators=[DataRequired()])
    shared_with_id = StringField('User ID to share with', validators=[DataRequired()])
    submit = SubmitField('Share')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/home")
@app.route("/")
def index():
    return render_template('home.html')

@app.route('/add', methods=["GET", "POST"])
@login_required
def add():
    form = ExpenseForm()
    if form.validate_on_submit():
        expense = Expense(title=form.title.data, category=form.category.data, amount=form.amount.data, date=form.date.data, author=current_user)
        db.session.add(expense)
        db.session.commit()
        flash('Your expense has been added!', 'success')
        return redirect(url_for('profile'))
    return render_template('add.html', title='Add Expense', form=form)

@app.route("/update/<int:expense_id>", methods=["GET", "POST"])
@login_required
def update(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.author != current_user:
        abort(403)
    form = ExpenseForm()
    if form.validate_on_submit():
        expense.title = form.title.data
        expense.category = form.category.data
        expense.amount = form.amount.data
        expense.date = form.date.data
        db.session.commit()
        flash('Your expense has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.title.data = expense.title
        form.category.data = expense.category
        form.amount.data = expense.amount
        form.date.data = expense.date
    return render_template('add.html', title='Update Expense', form=form)

@app.route("/delete/<int:expense_id>", methods=['POST'])
@login_required
def delete(expense_id):
    expense_to_delete = Expense.query.get_or_404(expense_id)
    if expense_to_delete.author != current_user:
        abort(403)
    try:
        db.session.delete(expense_to_delete)
        db.session.commit()
        flash('Expense has been deleted!', 'success')
        return redirect(url_for('profile'))
    except Exception as e:
        flash(f"There was a problem deleting that expense: {e}", 'danger')
        return redirect(url_for('profile'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('profile'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = SearchForm()
    expenses = []
    if form.validate_on_submit():
        search_term = form.search_term.data
        expenses = Expense.query.filter(
            Expense.user_id == current_user.id,
            Expense.title.ilike(f"%{search_term}%")
        ).order_by(Expense.date.desc()).all()
    else:
        expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()

    expenses_by_month = defaultdict(list)
    for expense in expenses:
        month = expense.date.strftime('%B %Y')
        expenses_by_month[month].append(expense)

    return render_template('profile.html', expenses_by_month=expenses_by_month, form=form)


@app.route("/stats", methods=['GET', 'POST'])
@login_required
def stats():
    form = TimeRangeForm()
    category_totals = []
    if form.validate_on_submit():
        time_range = form.time_range.data
        today = datetime.today()

        if time_range == 'last_month':
            start_date = today - timedelta(days=30)
        elif time_range == 'last_year':
            start_date = today - timedelta(days=365)
        else:
            start_date = today  

        category_totals = db.session.query(
            Expense.category, db.func.sum(Expense.amount).label('total')
        ).filter(
            Expense.user_id == current_user.id,
            Expense.date >= start_date
        ).group_by(Expense.category).all()

    return render_template('stats.html', category_totals=category_totals, form=form)


@app.route('/share_stats', methods=['GET', 'POST'])
@login_required
def share_stats():
    form = ShareStatsForm()
    if form.validate_on_submit():
        today = datetime.today()
        start_date = today - timedelta(days=30)
        category_totals = db.session.query(
            Expense.category, func.sum(Expense.amount).label('total')
        ).filter(
            Expense.user_id == current_user.id,
            Expense.date >= start_date,
            Expense.date <= today
        ).group_by(Expense.category).all()

        shared_user = User.query.filter_by(id=form.shared_with_id.data).first()
        if shared_user and shared_user.username == form.shared_with_username.data:
            for category, total in category_totals:
                existing_shared_stat = SharedStats.query.filter_by(
                    owner_id=current_user.id,
                    shared_with_username=form.shared_with_username.data,
                    shared_with_id=form.shared_with_id.data,
                    category=category
                ).first()

                if existing_shared_stat:
                    existing_shared_stat.amount = total
                else:
                    shared_stat = SharedStats(
                        owner_id=current_user.id,
                        shared_with_username=form.shared_with_username.data,
                        shared_with_id=form.shared_with_id.data,
                        category=category,
                        amount=total
                    )
                    db.session.add(shared_stat)

            db.session.commit()
            flash(f'Statistics shared successfully with {form.shared_with_username.data}!', 'success')
            return redirect('/profile')
        else:
            flash(f'User with username {form.shared_with_username.data} and ID {form.shared_with_id.data} not found.', 'danger')

    return render_template('share_stats.html', title='Share Stats', form=form)


@app.route('/view_shared_stats')
@login_required
def view_shared_stats():
    shared_stats = SharedStats.query.filter_by(shared_with_username=current_user.username).all()
    stats_by_user = defaultdict(list)
    for stat in shared_stats:
        stats_by_user[stat.owner_id].append(stat)
    
    users = User.query.filter(User.id.in_(stats_by_user.keys())).all()
    user_dict = {user.id: user.username for user in users}

    return render_template('view_shared_stats.html', title='Shared Stats', stats_by_user=stats_by_user, user_dict=user_dict)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect('/home')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
