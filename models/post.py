from google.appengine.ext import ndb
from models.user import User

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    author = ndb.KeyProperty(kind=User,required = True)
    likes = ndb.IntegerProperty(default=0)    

    def render_text(self):
        return self.content.replace('\n', '<br>')

    def author_name(self):
        return User._by_id(self.author.id()).name
