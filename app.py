from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import markdown as md
import bleach as bl

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def render_safe_markdown(text):
    raw_html = md.markdown(text or '', extensions=['fenced_code', 'codehilite', 'tables'])

    allowed_tags = list(bl.sanitizer.ALLOWED_TAGS) + [
        'p', 'pre', 'code', 'span', 'div',
        'h1', 'h2', 'h3', 'h4', 'h5',
        'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'blockquote', 'hr', 'br', 'ul', 'ol', 'li', 'img'
    ]

    allowed_attributes = dict(bl.sanitizer.ALLOWED_ATTRIBUTES)
    allowed_attributes.update({
        '*': ['class'],
        'a': ['href', 'title', 'rel'],
        'img': ['src', 'alt', 'title']
    })

    cleaned = bl.clean(
        raw_html,
        tags=allowed_tags,
        attributes=allowed_attributes,
        protocols=['http', 'https', 'mailto'],
        strip=True
    )
    return bl.linkify(cleaned)


@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    for post in posts:
        post.rendered_content = render_safe_markdown(post.content)
    return render_template('index.html', posts=posts)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        post = Post(title=title, content=content, author=current_user)
        db.session.add(post)
        db.session.commit()

        flash('Post created successfully!', 'success')
        return redirect(url_for('view_post', post_id=post.id))

    return render_template('new_post.html')


# python
@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()

    safe_html  = render_safe_markdown(post.content)
    for comment in comments:
        comment.rendered_content = render_safe_markdown(comment.content)

    return render_template('view_post.html', post=post, comments=comments, rendered_content=safe_html)

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        flash('You can only edit your own posts', 'error')
        return redirect(url_for('view_post', post_id=post_id))

    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Post updated successfully!', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    return render_template('edit_post.html', post=post)


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    if post.author != current_user:
        flash('You can only delete your own posts', 'error')
        return redirect(url_for('view_post', post_id=post_id))

    db.session.delete(post)
    db.session.commit()

    flash('Post deleted successfully', 'success')
    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')

    comment = Comment(content=content, author=current_user, post=post)
    db.session.add(comment)
    db.session.commit()

    flash('Comment added successfully!', 'success')
    return redirect(url_for('view_post', post_id=post_id))


@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if comment.author != current_user:
        flash('You can only delete your own comments', 'error')
        return redirect(url_for('view_post', post_id=comment.post_id))

    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()

    flash('Comment deleted successfully', 'success')
    return redirect(url_for('view_post', post_id=post_id))


@app.route('/users')
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)


@app.route('/user/<int:user_id>')
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = Post.query.filter_by(user_id=user_id).order_by(Post.created_at.desc()).all()
    return render_template('user_profile.html', user=user, posts=posts)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        import os

        print("USING DB PATH:", os.path.abspath("blog.db"))

        # Create sample user and post if database is empty
        if User.query.count() == 0:
            sample_user = User(username='demo', email='demo@example.com')
            sample_user.set_password('demo123')
            db.session.add(sample_user)
            db.session.commit()

            sample_post = Post(title='Understanding Flask-Login: A Deep Dive', content='''# Flask-Login: Simplifying User Authentication

When building this blog application, one of the most critical features was user authentication. I chose **Flask-Login** as my authentication library, and in this post, I'll share my experience implementing it, the challenges I faced, and why it's an excellent choice for Flask applications.

## What is Flask-Login?

Flask-Login is a Flask extension that handles the common tasks of logging users in and out, remembering their sessions, and restricting access to certain pages. It doesn't handle user registration, password resets, or other authentication details—it focuses solely on session management.

## Implementation Challenges

### Challenge 1: Understanding UserMixin
The `UserMixin` class provides default implementations for the methods that Flask-Login expects. Initially, I tried implementing these methods manually (`is_authenticated`, `is_active`, `is_anonymous`, `get_id`), which was tedious and error-prone. Switching to `UserMixin` simplified the code significantly.

### Challenge 2: Password Security
Storing passwords securely was crucial. I used Werkzeug's `generate_password_hash()` and `check_password_hash()` functions to ensure passwords are never stored in plain text. This added a layer of security that's essential for any production application.

### Challenge 3: Protecting Routes
The `@login_required` decorator makes it easy to protect routes, but I had to carefully consider which routes should be public (like viewing posts) versus private (like creating posts).

## Alternative Options

### Manual Session Management
Without Flask-Login, I would need to manually manage sessions using Flask's session object. This involves:
- Storing user IDs in sessions
- Checking session validity on each request
- Implementing logout functionality manually
- Handling "remember me" functionality

This approach is more work and prone to security issues.

### Flask-User
Flask-User is a more comprehensive solution that includes registration, password resets, and email confirmation. While powerful, it was overkill for this project. Flask-Login's focused approach gave me more control over the authentication flow.

### Flask-Security
Another alternative is Flask-Security, which combines several extensions including Flask-Login. It's feature-rich but adds complexity. For a learning project, Flask-Login's simplicity was perfect.

## Key Takeaways

1. **Flask-Login excels at one thing**: session management. It doesn't try to do everything, which makes it flexible and easy to understand.

2. **The `login_manager.user_loader` decorator** is essential—it tells Flask-Login how to reload a user object from the user ID stored in the session.

3. **Template integration** is seamless. The `current_user` proxy makes it easy to check authentication status in Jinja2 templates.

## Code Example

Here's how simple it is to set up Flask-Login:

```python
from flask_login import LoginManager, login_user, logout_user

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

## Conclusion

Flask-Login strikes the perfect balance between simplicity and functionality. For this blog project, it provided everything I needed without unnecessary complexity. If you're building a Flask application that needs authentication, I highly recommend giving Flask-Login a try!''',
                author=sample_user)
            db.session.add(sample_post)
            db.session.commit()

            print('Sample user created: username=demo, password=demo123')

    app.run(debug=True)
