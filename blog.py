import os
import re
import time
from string import letters
import hashlib
import hmac
import random

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

SECRET = 'pblog'

#Basic functions including hash the username and hash the password

#Make a hash code for the input value
def makeHash(val):
	return '%s,%s' % (val, hmac.new(SECRET, val).hexdigest())

#Check if the hash code can match the value so that the cookie in the website 
#can not be changed easily
def checkHash(pair):
	val = pair.split(',')[0]
	if pair == makeHash(val):
		return val

#Make a random secret message - salt
def make_salt(len):
	return ''.join(random.choice(letters) for x in xrange(len))

#Hash the password including the username, password and the salt
def hashPw(name, password, salt = None):
	if not salt:
		salt = make_salt(5)
	h = hashlib.sha256(name + password + salt).hexdigest()
	return '%s,%s' % (salt, h)

#Chech if the hash value can match the input value
def validPw(name, password, h):
	salt = h.split(',')[0]
	return h == hashPw(name, password, salt)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

#It is the basic handler for all other classes
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render(self, template, **kw):
		self.response.write(render_str(template, **kw))

#This part is used to set cookie to store the user information
	def setCookie(self, name, val):
		if val:
			cookie_val = makeHash(val)
		else:
			cookie_val = ''
		self.response.headers.add_header('Set-Cookie', '%s=%s' %(name, cookie_val))

#The cookie is used to store the name of the user so that 
#welcome page will show the username
#This part also include the function of set cookie and delete cookie.
	def addNameCookie(self, val):
		self.response.headers.add_header('Set-Cookie', '%s=%s' %('username', val))

	def getCookie(self, name):
		if name in self.request.cookies:
			return self.request.cookies.get(name)

	def checkCookie(self, name):
		coo = self.request.cookies.get(name)
		return coo and checkHash(coo)

	def clearCookie(self):
		self.setCookie('user_id', '')

	def login(self, user):
		self.setCookie('user_id', str(user.key().id()))

	def logout(self):
		self.clearCookie()

	def initialize(self, *a, **kw):
	    webapp2.RequestHandler.initialize(self, *a, **kw)
	    uid = self.getCookie('user_id')
	    self.user = uid and User.byId(int(uid))

#Twit is used to store the twit datatype, including the subject, 
#content and creating time and users who post the twit and 
#the number of like
class Twit(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	username = db.StringProperty(required = True)
	like = db.IntegerProperty(required = True)

	@classmethod
	def addTwit(cls, subject, content, username, like = 0):
		twit = Twit(subject=subject, content=content, username=username, like=like)
		twit.put()
		return twit


class Comment(db.Model):
	comment = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	twit = db.IntegerProperty(required = True)
	who = db.StringProperty(required = True)

	@classmethod
	def byTwit(cls, twit):
		tw = Comment.all().filter('twit =', twit).get();
		return tw

#Database User is used to store the information about users, 
#including their username, their hash 
#password, their email. liked is the property that their liked twits.
class User(db.Model):
	name = db.StringProperty(required = True)
	pwHash = db.StringProperty(required = True)
	liked = db.StringProperty()
	email = db.StringProperty()

	@classmethod
	def byId(cls, uId):
		return User.get_by_id(uId)

	@classmethod
	def byName(cls, name):
		u = User.all().filter('name =', name).get();
		return u

	@classmethod
	def register(cls, name, password, email = None):
		pwHash = hashPw(name, password)
		return User(name=name, pwHash=pwHash, email=email)

	@classmethod
	def login(cls, name, password):
		u = cls.byName(name)
		if u and validPw(name, password, u.pwHash):
			return u

#The Like is used to store the property of like between the 
#specific user and a specific twit.
#like is combined by user id and twit id
class Like(db.Model):
	like = db.StringProperty(required = True)

	@classmethod
	def byLike(cls, likemsg):
		lk = Like.all().filter('like =', likemsg).get();
		return lk


#HomePage is the main page of the blog, including show 
#the box of submit subject and content
#This page also include all the twits
#For each twit, user can like, unlike others twits, 
#edit and delete their own twits and comment on any twit
#If user want to post a new twit, subject and content are required


class Post(Handler):
	def render_text(self,subject="",content="",error_sj="",error_ct="",name=""):
		user = self.getCookie(name='user_id')
		u = User.byId(int(user))
		name = u.name
		self.render("Post.html",subject=subject,content=content,error_sj=error_sj,
					error_ct=error_ct,name=name)

	def get(self):
		if not self.user:
			return self.redirect('/signin')
		self.render_text()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		username = self.getCookie(name='user_id')
		logout_old = self.request.get("logout_old")
		back = self.request.get("back")
		err = False

		if not username:
			return self.redirect('/signin')		

		if logout_old:
			return self.redirect('/signout')

		if back:
			return self.redirect('/homepage')

		if not subject:
			error_sj = "Invalid subject!"
			err = True
		if not content:
			error_ct = "Invalid content!"
			err = True

		if err:
			self.render_text(subject,content,error_sj,error_ct)
		else:
			twit = Twit(subject=subject,content=content,username=username,like=0)
			twit.put()
			time.sleep(0.1)
			return self.redirect('/twit/%s' % str(twit.key().id()))

class HomePage(Handler):
	def render_front(self, name=""):
		twits = db.GqlQuery("select * from Twit order by created desc")
		cms = db.GqlQuery("select * from Comment order by created desc")
		user = self.getCookie(name='user_id')
		u = User.byId(int(user))
		name = u.name
		self.render("HomePage.html",name=name,twits=twits,cms=cms)

	def get(self):
		if not self.user:
			return self.redirect('/signin')
		self.render_front()

	def post(self):
		like_num = self.request.get("like")
		unlike_num = self.request.get("unlike")
		username = self.getCookie(name='user_id')
		delete = self.request.get("delete")
		edit = self.request.get("edit")
		li = self.request.get("logout_old")
		comment = self.request.get("comment")
		t_id = self.request.get("id")
		delete_cm = self.request.get("delete_cm")
		edit_cm = self.request.get("edit_cm")
		post = self.request.get("post")

		if not username:
			return self.redirect('/signin')

		if post:
			return self.redirect('/post')

		if comment:
			return self.redirect('/Cmt/%s,%s,%s' % (comment, t_id, username))

		if edit_cm:
			return self.redirect('/Ecmt/%s,%s' % (edit_cm, username))

		if delete_cm:
			return self.redirect('/Dcmt/%s,%s' % (delete_cm, username))

		if li:
			return self.redirect('/signout')

		if like_num:
			return self.redirect('/Lt/%s,%s' % (like_num, username))

		if unlike_num:
			return self.redirect('/ULt/%s,%s' % (unlike_num, username))

		if delete:
			return self.redirect('/Dt/%s,%s' % (delete, username))

		if edit:
			return self.redirect('/Et/%s,%s' % (edit, username))

class EditTwit(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		edit = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Twit', int(edit))
		twit = db.get(key)
		if twit and username == twit.username:
			return self.redirect('/twit/%s' % edit)
		else:
			return self.redirect('/homepage')

class DeleteTwit(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		delete = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Twit', int(delete))
		twit = db.get(key)
		if twit and username == twit.username:
			twit.delete()
			cm = Comment.byTwit(str(delete))
			if cm:
				cm.delete()
		time.sleep(0.1)
		return self.redirect('/homepage')

class UnlikeTwit(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		unlike_num = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Twit', int(unlike_num))
		twit = db.get(key)
		lkmsg = username + ',' + unlike_num
		lk = Like.byLike(lkmsg)
		if lk and twit and username != twit.username:
			twit.like -= 1
			twit.put()
			lk.delete()
		time.sleep(0.1)
		return self.redirect('/homepage')


class LikeTwit(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		like_num = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Twit', int(like_num))
		twit = db.get(key)
		lkmsg = username + ',' + like_num
		lk = Like.byLike(lkmsg)
		if not lk and twit and username != twit.username:
			twit.like += 1
			Like(like=lkmsg).put()
			twit.put()
		time.sleep(0.1)
		return self.redirect('/homepage')

class addComment(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		comment = c.split(',')[0]
		t_id = int(c.split(',')[1])
		username = c.split(',')[2]
		cm = Comment(comment=comment,twit=t_id,who=username)
		cm.put()
		time.sleep(0.1)
		self.redirect('/homepage')

class EditComment(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		edit_cm = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Comment', int(edit_cm))
		com = db.get(key)
		if com and com.who == username:
			return self.redirect('/com/%s' % edit_cm)
		else:
			return self.redirect('/homepage')

class DeleteComment(HomePage):
	def get(self, c):
		if not self.user:
			return self.redirect('/signin')
		delete_cm = c.split(',')[0]
		username = c.split(',')[1]
		key = db.Key.from_path('Comment', int(delete_cm))
		com = db.get(key)
		if com and com.who == username:
			com.delete()
		time.sleep(0.1)
		return self.redirect('/homepage')


class ComEdit(Handler):
	def get(self, com_id):
		if not self.user:
			return self.redirect('/signin')
		user = self.getCookie('user_id')
		if not user:
			return self.redirect('/signin')
		key = db.Key.from_path('Comment', int(com_id))
		com = db.get(key)
		if not com:
			self.error(404)
			return
		self.render("commentEdit.html", com=com)

	def post(self, *a):
		comment = self.request.get("comment")
		cmid = self.request.get("id")
		user = self.getCookie('user_id')
		if not user:
			return self.redirect('/signin')

		if cmid:
			key = db.Key.from_path('Comment', int(cmid))
			com = db.get(key)
			if com and comment:
				com.comment = comment
			com.put()
		time.sleep(0.1)
		return self.redirect('/homepage')

#The singlepage is used to store the single twit user is adding or editing.
#When user want to edit the twit, subject or content are not necessary. 
#They can input either subject or content, no error information will appear
class SinglePage(Handler):
	def get(self, twit_id):
		user = self.getCookie(name='user_id')
		u = User.byId(int(user))
		name = u.name
		user = self.getCookie(name='user_id')
		if not user:
			return self.redirect('/signin')
		key = db.Key.from_path('Twit', int(twit_id))
		twit = db.get(key)
		if not twit:
			self.error(404)
			return
		self.render("SingleTwit.html", twit=twit, name=name)

	def post(self, *a):
		subject = self.request.get("subject")
		content = self.request.get("content")
		twit_id = self.request.get("id")
		cancel = self.request.get("cancel")
		bh = self.request.get("backhome")
		user = self.getCookie(name='user_id')

		if not user:
			return self.redirect('/signin')

		if cancel:
			return self.redirect('/homepage')

		if not subject or not content:
			return self.redirect('/homepage')

		if bh:
			return self.redirect('/homepage')

		if twit_id:
			key = db.Key.from_path('Twit', int(twit_id))
			twit = db.get(key)
			if subject:
				twit.subject = subject
			if content:
				twit.content = content
			twit.put()
		time.sleep(0.2)
		return self.redirect('/homepage')


##Make sure the register information is reasonable
UN_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and UN_RE.match(username)

PW_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PW_RE.match(password)

def valid_verify(verify, password):
	return verify == password

EM_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
	return not email or EM_RE.match(email)


#SignUp page is used to register with new user. 
#Username must be different from registered users.
class SignUp(Handler):
	def get(self, **params):
		self.render("SignUp.html", **params)

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		rg = self.request.get('register_new')
		li = self.request.get('login_old')
		err_signUp = False
		params = dict(username = username, email = email)

		if rg:
			return self.redirect('/')
		if li:
			return self.redirect('/signin')

		if not valid_username(username):
			params['error_un'] = "Invalid Username!!"
			err_signUp = True
		if not valid_password(password):
			params['error_pw'] = "Invalid Password!!"
			err_signUp = True
		if not valid_verify(password, verify):
			params['error_vy'] = "Invalid Verify!!"
			err_signUp = True
		if not valid_email(email):
			params['error_em'] = "Invalid Email"
			err_signUp = True

		if err_signUp:
			self.render("SignUp.html", **params)
		else:
			u = User.byName(username)
			if u:
				params['error_un'] = 'Username already existed!'
				self.render("SignUp.html", **params)
			else:
				u = User.register(username, password, email)
				u.put()
				self.login(u)
				self.addNameCookie(str(username))
				return self.redirect('/homepage')


#SignIn is used to log in by the registered user.
class SignIn(Handler):
	def get(self):
		self.render("SignIn.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		rg = self.request.get("register_new")
		li = self.request.get("login_old")


		if rg:
			return self.redirect('/')
		if li:
			return self.redirect('/signin')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.addNameCookie(str(username))
			self.redirect('/homepage')
		else:
			error_lg = "Invalid login"
			self.render("SignIn.html", error_lg=error_lg)

#SignOut is used to clear the cookie and log out
class SignOut(Handler):
	def get(self):
		self.logout()
		return self.redirect('/signin')

app = webapp2.WSGIApplication([('/', SignUp),
							   ('/homepage', HomePage),
							   ('/twit/([0-9]+)', SinglePage),
							   ('/signin', SignIn),
							   ('/signout', SignOut),
							   ('/com/([0-9]+)', ComEdit),
							   ('/post', Post),
							   ('/Cmt/([0-9a-zA-Z,]+)', addComment),
							   ('/Ecmt/([0-9a-zA-Z,]+)', EditComment),
							   ('/Dcmt/([0-9a-zA-Z,]+)', DeleteComment),
							   ('/Lt/([0-9a-zA-Z,]+)', LikeTwit),
							   ('/ULt/([0-9a-zA-Z,]+)', UnlikeTwit),
							   ('/Dt/([0-9a-zA-Z,]+)', DeleteTwit),
							   ('/Et/([0-9a-zA-Z,]+)', EditTwit)],
							   debug=True)