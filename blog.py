import os
import re
import random
import hashlib
import hmac
import string
from string import letters

import webapp2
import jinja2

from google.appengine.ext import ndb

from models.user import User
from models.post import Post
from models.comment import Comment

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

    def user_owns_post(self, post):
        return self.user.key == post.author

    def comment_exists(self, comment):
        return self.user.key == comment.author

    def post_exists(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        return post
    
    # def post_exists(function):
    #     @wraps(function)
    #     def wrapper(self, post_id):
    #         key = ndb.Key('Post', int(post_id), parent=blog_key())
    #         post = key.get()
    #         if post:
    #             return function(self, post_id, post)
    #         else:
    #             self.error(404)
    #             return
    #     return wrapper

# Keys - used to ensure strong consistency

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

def comment_key(name='default'):
    return ndb.Key('comments', name)

class DeleteAccount(BlogHandler):
    def post(self):
        key = ndb.Key('User', int(self.user.key.id()), parent=users_key())

        #delete all associated posts
        p_query = Post.query(Post.author == self.user.key)
        for p in p_query:
            delete_key = ndb.Key('Post', int(p.key.id()), parent=blog_key())
            delete_key.delete()
        
        # delete user
        key.delete()
        self.redirect('/login')

# User home page

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            # Display all posts from currently logged in user
            p_query = Post.query(Post.author == self.user.key)
            posts = p_query.fetch()

            # Display list of posts that the user has liked
            likes = []
            if not self.user.likes:
                likes = False
            else:
                for like in self.user.likes:
                    key = ndb.Key('Post', int(like), parent=blog_key())
                    post = key.get()
                    likes.append(post)
            
            self.render('welcome.html', 
                username = self.user.name, 
                current_user = self.user.name, 
                posts = posts, 
                likes = likes
                )
        else:
            self.redirect('/signup')

# Main blog page

class BlogFront(BlogHandler):
    def get(self):
        # post_query = Post.query(ancestor=blog_key()).order(-Post.last_modified)
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
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()

        comments_q = ndb.gql("SELECT * FROM Comment WHERE comment_post_key = :1",key)
        comments = comments_q.fetch(10)
        like_value = "Like"
        like_name = "like"
        current_user = ""
        if self.user:
            current_user = self.user.name
            like_list = self.user.likes
            if like_list:
                for like in like_list:
                    if like == int(post_id):
                        like_name = "unlike"
                        like_value = "Unlike"

        if not post:
            self.error(404)
            return

        self.render("post.html", 
            post = post,
            author = post.author_name(), 
            current_user = current_user, 
            like_value = like_value, 
            like_name = like_name,
            comments = comments
            )

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", 
                current_user = self.user.name)
        else:
            # checks if user has logged out in another window but attempts to post in a logged in window
            self.redirect("/login?error=notloggedin")

    def post(self):
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
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
    # @post_exists --> when attempting to use the decorator function the error name "post_exists" is not defined.. not sure why
    def get(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        # check whether or not the provided post id exists before going any further
        if not post:
            self.redirect('/')
        if not self.user.key == post.author:
            error = "You are not allowed to edit this post!"
            self.render("editpost.html", post=post, error=error, disabled = True)
        else:
            self.render("editpost.html", post=post, current_user = self.user.name)

    def post(self,post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        if not self.user_owns_post(post):
            self.redirect('/')
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
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
    def post(self):
        delete_id = self.request.get('id')
        key = ndb.Key('Post', int(delete_id), parent=blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
            key.delete()
            self.redirect('/blog')

class LikePost(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
            post_id = self.request.get('id')
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            # Get the user
            u = ndb.Key('User', self.user.key.id(), parent=users_key())
            user = u.get()

            # Set the likes accordingly
            if self.request.get('like') == "Like":
                post.likes = post.likes + 1
                user.add_like(int(post_id))
            else:
                post.likes = post.likes - 1
                user.remove_like(int(post_id))

            post.put()
            user.put()
            self.redirect('/blog/%s' % str(post_id))

# Comment classes

class NewComment(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
            post_id = int(self.request.get('id'))
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            if not post:
                self.error(404)
                return
            comment_post_key = ndb.Key('Post', post_id, parent=blog_key())
            comment_text = self.request.get('comment_text')
            update_comment = self.request.get('update_comment_id')

            if update_comment:
                key = ndb.Key('Comment', int(update_comment), parent=comment_key())
                comment = key.get()
                comment.comment_text = comment_text
                comment.put()
                self.redirect('/blog/%s' % str(post_id))

            else:
                c = Comment(
                    parent = comment_key(),
                    comment_text = comment_text,
                    comment_author = self.user.key,
                    comment_post_key = comment_post_key
                    )
                c.put()
                self.redirect('/blog/%s' % str(post_id))

class DeleteComment(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect('/login?error=notloggedin')
        else:
            delete_id = self.request.get('comment_id')
            post_id = self.request.get('post_id')
            key = ndb.Key('Comment', int(delete_id), parent=comment_key())
            key.delete()
            self.redirect('/blog/%s' % str(post_id))

# User registration and login classes

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
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
                               ('/blog/deletecomment', DeleteComment),
                               ('/deleteaccount', DeleteAccount),
                               ('/blog/likepost', LikePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
