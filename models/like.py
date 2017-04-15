from google.appengine.ext import ndb
from models.user import User
from models.post import Post

def blog_key(name = 'default'):
    return ndb.Key('blogs', name)

class Like(ndb.Model):
	like_count = ndb.IntegerProperty(default=0)
	post_key = ndb.KeyProperty(kind=Post,required=True)
	liked_by_key = ndb.KeyProperty(kind=User, repeated=True) # [ 1,3,4,5, 6]

	@classmethod
	# gets the like entity by post id 
	def get_by_postid(cls,post_id):
		key = ndb.Key('Post', int(post_id), parent=blog_key())
		l = Like.query(Like.post_key == key).get()
		return l

	@classmethod
	def liked_posts(cls,user_key):
		likes = []
		like_query = ndb.gql("SELECT * FROM Like")
		fetch = like_query.fetch()

		for l in fetch:
			if user_key in l.liked_by_key:
				likes.append(l.post_key)
		return likes
	