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
    
    # @property # this allows you to call this method without using (), so it will look like a variable
    # def likes(self):
    #     return 

    @property # this allows you to call this method without using (), so it will look like a variable
    def comments(self):
        comments_q = ndb.gql("SELECT * FROM Comment WHERE comment_post_key = :1",self.key)
        return comments_q.fetch(10)