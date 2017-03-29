import re
import random
import hashlib
import hmac
import string
from string import letters
from google.appengine.ext import ndb

class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    likes = ndb.JsonProperty(default=[])
    posts = ndb.JsonProperty(default=[])

    def add_like(self,post_id):
        self.likes.append(post_id)
        return

    def remove_like(self,post_id):
        self.likes.remove(post_id)
        return

    @classmethod
    def _by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def _by_name(cls, name):
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def _register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def _login(cls, name, pw):
        u = cls._by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def users_key(group = 'default'):
    return ndb.Key('users', group)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)