import os
import re
import random
import hashlib
import hmac
import string
from string import letters
from functools import wraps
import webapp2
import jinja2

from google.appengine.ext import ndb

from models.user import User
from models.post import Post
from models.comment import Comment
from models.like import Like

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SECRET = '5tsdf8cjdfsie9'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Hashing functions

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Main handler

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))
        self.set_secure_cookie('name', str(user.name))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'name=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User._by_id(int(uid))


#Decorators

def post_exists(function):
    @wraps(function)
    def wrapper(self, post_id=''):
        if not post_id:
            post_id = self.request.get('post_id')
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if post:
            return function(self, post_id, post)
        else:
            return self.redirect('/login?error=notloggedin')
            
    return wrapper

def user_owns_post(function):
    @wraps(function)
    def wrapper(self, post_id='', post=''):
        if self.user.key == post.author:
            return function(self, post_id, post)
        else:
            self.error(404)
            return
    return wrapper

def user_logged_in(function):
    @wraps(function)
    def wrapper(self, post_id='', post=''):
        if self.user:
            return function(self, post_id, post)
        else:
            return self.redirect('/login?error=notloggedin')
    return wrapper

def comment_exists(function):
    @wraps(function)
    def wrapper(self,post_id,post):
        comment_id = self.request.get('comment_id')
        comment = Comment.get_by_id(int(comment_id), parent=comment_key())
        
        if comment and post:
            return function(self, post_id, post, comment)
        else:
            self.error(404)
            return
    return wrapper

def user_owns_comment(function):
    @wraps(function)
    def wrapper(self,post_id,post,comment):
        if self.user.key.id() == comment.comment_author.id():
            return function(self, post_id, post, comment)
        else:
            self.error(404)
            return
    return wrapper
        

# Keys - used to ensure strong consistency

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

def comment_key(name='default'):
    return ndb.Key('comments', name)

def like_key(name='default'):
    return ndb.Key('likes', name)

def users_key(group = 'default'):
    return ndb.Key('users', group)

class DeleteAccount(BlogHandler):
    def post(self):
        user = User.get_by_id(int(self.user.key.id()), parent=users_key())

        #delete all associated posts
        p_query = Post.query(Post.author == self.user.key)
        if p_query:
            for p in p_query:
                Post.get_by_id(int(p.key.id()), parent=blog_key()).key.delete()
        
        #delete all associated comments
        c_query = Comment.query(Comment.comment_author == self.user.key)
        if c_query:
            for c in c_query:
                Comment.get_by_id(int(c.key.id()), parent=comment_key()).key.delete()
        
        # delete user
        user.key.delete()
        self.redirect('/login')

# User home page

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            # Display all posts created by currently logged in user
            p_query = Post.query(Post.author == self.user.key)
            posts = p_query.fetch()

            # Display list of posts that the user has liked
            likes = Like.liked_posts(self.user.key)
            liked_posts = []
            for l in likes:
                liked_posts.append(Post.get_by_id(int(l.id()), parent=blog_key()))
            
            self.render('welcome.html', 
                username = self.user.name, 
                current_user = self.user.name, 
                posts = posts,
                likes = liked_posts
                )
        else:
            self.redirect('/signup')

# Main blog page

class BlogFront(BlogHandler):
    def get(self):
        p_query = ndb.gql("SELECT * FROM Post")
        posts = p_query.fetch()

        if self.user:
            self.render('front.html',
                        posts = posts, 
                        current_user = self.user.name
                        )
        else:
            self.render('front.html',
                        posts = posts
                        )

# Post handlers

class PostPage(BlogHandler):
    @post_exists
    def get(self, post_id, post):
        like_value = "Like"
        like_name = "like"

        likes = Like.get_by_postid(post_id)
    
        if likes:
            if self.user.key in likes.liked_by_key:
                like_value = "Unlike"
                like_name = "unlike"

        if self.user:
            self.render("post.html", 
                post = post,
                author = post.author_name(), 
                current_user = self.user.name,
                like_value = like_value, 
                like_name = like_name,
                likes = likes
                )
        else:
            self.render("post.html", 
                post = post,
                author = post.author_name(),
                likes = likes
                )

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", 
                current_user = self.user.name)
        else:
            # checks if user has logged out in another window but attempts to post in a logged in window
            self.redirect("/login?error=notloggedin")
    @user_logged_in
    def post(self,post_id,post):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.key

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = author)
            p.put()
            self.redirect('/blog/%s' % str(p.key.id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", 
                subject=subject, 
                content=content, 
                error=error, 
                current_user = self.user.name)

class EditPost(BlogHandler):
    @post_exists
    @user_logged_in
    @user_owns_post
    def get(self,post_id,post):
        self.render("editpost.html", post=post, current_user = self.user.name)
    
    @post_exists
    @user_logged_in    
    @user_owns_post
    def post(self,post_id,post):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key.id()))
        else:
            error = "You must fill both fields!"
            self.render("editpost.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
    @post_exists
    @user_logged_in   
    @user_owns_post
    def post(self,post_id,post):
        post.key.delete()
        self.redirect('/blog')
        

class LikeHandler(BlogHandler):
    @post_exists
    @user_logged_in 
    def post(self,post_id,post):
        # makes sure the user isn't able to like their own post, logs them out with an error for trying to cheat
        if self.user.key == post.author:
            self.logout()
            return self.redirect('/login?error=fakelike')
        if not Like.get_by_postid(post_id):
            l = Like(parent = like_key(), like_count = 1, post_key=post.key, liked_by_key=[self.user.key])
            l.put()
            return self.redirect('/blog/%s' % int(post_id))
        else:
            like = Like.get_by_postid(post_id)
            if self.user.key in like.liked_by_key:
                like.like_count -= 1
                like.liked_by_key.remove(self.user.key)
                like.put()
                return self.redirect('/blog/%s' % int(post_id))
            else:
                like.like_count += 1
                like.liked_by_key.append(self.user.key)
                like.put()
                return self.redirect('/blog/%s' % int(post_id))


# Comment classes

class NewComment(BlogHandler):
    @post_exists
    @user_logged_in
    def post(self,post_id,post):
        comment_text = self.request.get('comment_text')
        if comment_text:
            c = Comment(
                parent = comment_key(),
                comment_text = comment_text,
                comment_author = self.user.key,
                comment_post_key = post.key
                )
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            self.error(404)
            return

class UpdateComment(BlogHandler):
    @post_exists
    @user_logged_in
    @comment_exists
    @user_owns_comment
    def post(self,post_id,post,comment):
        comment_text = self.request.get('comment_text')
        comment.comment_text = comment_text
        comment.put()
        self.redirect('/blog/%s' % str(post_id))

class DeleteComment(BlogHandler):
    @post_exists
    @user_logged_in
    @comment_exists
    @user_owns_comment
    def post(self, post_id, post, comment):    
        comment.key.delete()
        self.redirect('/blog/%s' % str(post_id))

# User registration and login classes

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)

def valid_email(email):
    EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User._by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User._register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        error = self.request.get('error')
        if error == 'notloggedin':
            error="You must be logged in to do that."
        elif error == 'fakelike':
            error="You cannot like your own post"
        self.render('login.html', error = error)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User._login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class MainPage(BlogHandler):
  def get(self):
    if self.user:
        self.redirect('/welcome')
    else:
        self.redirect('/login')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/postcomment', NewComment),
                               ('/blog/updatecomment', UpdateComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/deleteaccount', DeleteAccount),
                               ('/blog/likepost', LikeHandler),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)