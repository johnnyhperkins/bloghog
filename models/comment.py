from google.appengine.ext import ndb
from models.user import User
from models.post import Post

class Comment(ndb.Model):
    comment_text = ndb.TextProperty(required = True)
    comment_created = ndb.DateTimeProperty(auto_now_add = True)
    comment_author = ndb.KeyProperty(kind=User, required = True)
    comment_post_key = ndb.KeyProperty(kind=Post, required = True)

    def render_text(self):
        return self.comment_text.replace('\n', '<br>')

    def author_name(self):
        return User._by_id(self.comment_author.id()).name