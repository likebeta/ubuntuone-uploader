#!/usr/bin/python

#Author:likebeta
#Data: 2014-01-11
#Email: ixxoo.me@gmail.com

import sys
import os
import argparse
import json
import oauth2
import urllib
import urllib2
import httplib
import base64
import hashlib
from getpass import getpass
from urlparse import urlparse, parse_qs
from mimetypes import guess_type

class UbuntuOne:
	def __init__(self,args):
		self.args = args

	def run(self):
		if self.args.command == 'auth':
			self.__auth()
		elif self.args.command == 'quota':
			self.__quota()
		elif self.args.command == 'list':
			self.__list()
		elif self.args.command == 'download':
			self.__download()
		elif self.args.command == 'upload':
			self.__upload()
		elif self.args.command == 'delete':
			self.__delete()	
		elif self.args.command == 'mkdir':
			self.__mkdir()
		elif self.args.command == 'move':
			self.__move()
		elif self.args.command == 'copy':
			self.__copy()
		elif self.args.command == 'share':
			self.__share()

	def __read_tokens(self, fin):
		dat = parse_qs(fin.readline().strip())
		self.consumer = oauth2.Consumer(dat['oauth_consumer_key'][0],dat['oauth_consumer_secret'][0])
		dat = parse_qs(fin.readline().strip())
		self.token = oauth2.Token(dat['oauth_token'][0],dat['oauth_token_secret'][0])

	def __sign_url(self, url):
		dat = urlparse(url)
		oauth_request = oauth2.Request.from_consumer_and_token(self.consumer, self.token, 'GET', url)
		oauth_request.sign_request(oauth2.SignatureMethod_PLAINTEXT(), self.consumer, self.token)
		return oauth_request, dat[1]

	def __get(self, url):
		surl, host = self.__sign_url(url)
		request = urllib2.Request(url)
		for header, value in surl.to_header().items():
			request.add_header(header, value)
		response = urllib2.urlopen(request)
		return response.read()

	def __put(self, url, data="", mime=""):
		sreq, host = self.__sign_url(url)
		conn = httplib.HTTPSConnection(host)
		header = dict(sreq.to_header().items())
		if mime:
			header["Content-Type"] = mime
		conn.request('PUT', url, data, header)
		res = conn.getresponse()
		return res.read()

	def __delete(self, url):
		sreq, host = self.__sign_url(url)
		conn = httplib.HTTPSConnection(host)
		hd = dict(sreq.to_header().items())
		conn.request('DELETE', url, '', hd)
		res = conn.getresponse()
		return res.read()

	def __acquire_token(self,fout):
		print "Please input email address and password to authorize"
		email_address = raw_input("Email:")
		password = getpass()
		request = urllib2.Request(
			'https://login.ubuntu.com/api/1.0/authentications?' +
			urllib.urlencode({'ws.op': 'authenticate',
			'token_name': 'Ubuntu One @ ubuntu [qunpin]'}))
		request.add_header('Accept', 'application/json')
		request.add_header('Authorization', 'Basic %s' % base64.b64encode(
			'%s:%s' % (email_address, password)))
		try:
			response = urllib2.urlopen(request)
		except urllib2.HTTPError, e:
			if e.code == 401:
				print("wrong email or password")
				return
			else:
				raise
		data = json.load(response)
		self.consumer = oauth2.Consumer(data['consumer_key'], data['consumer_secret'])
		self.token = oauth2.Token(data['token'], data['token_secret'])
		self.__get('https://one.ubuntu.com/oauth/sso-finished-so-get-tokens/')

		fout.truncate(0)
		fout.seek(0,os.SEEK_SET)
		fout.write(str(self.consumer))
		fout.write("\n")
		fout.write(self.token.to_string())
		fout.write("\n")
		print('authorize success')

	def __check_auth(self):
		with open('.ubuntuone','a+') as f:
			try:
				self.__read_tokens(f)
			except:
				self.__acquire_token(f)
		return True

	def __auth(self):
		with open('.ubuntuone','a+') as f:
			self.__acquire_token(f)
		return True

	def __quota(self):
		if not self.__check_auth():
			return

		resp = self.__get('https://one.ubuntu.com/api/quota/')
		infos = json.loads(resp)

		print("total:" + to_human_see(infos['total']))
		print("used:" + to_human_see(infos['used']))

	def __list(self):
		if not self.__check_auth():
			return

		if self.args.dir_path:
			dirname = self.args.dir_path
		else:
			dirname = ''

		resp = self.__get('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + dirname  + '?include_children=true')
		files = json.loads(resp)

		for item in files['children']:
			if item['kind'] == 'directory':
				print('%10s    %s'%('---',item['path'] + '/'))
			elif item['kind'] == 'file':
				print('%10s    %s'%(to_human_see(item['size']),item['path']))

	def __download(self):
		if not self.__check_auth():
			return
		
		resp = self.__get('https://files.one.ubuntu.com/content/~/Ubuntu%20One' + self.args.remote_path)
		sys.stdout.write(resp)

	def __upload(self):
		if not self.__check_auth():
			return

		if not os.path.isfile(self.args.local_path):
			print(self.args.local_path + ' is not file')
			return

		if self.args.remote_path:
			remote_path = self.args.remote_path
		else:
			remote_path = '/' + os.path.basename(self.args.local_path)

		while remote_path[-1] == '/':
			remote_path =  remote_path[0:-1]

		#magic upload test
		print('test magic upload with sha1 of ' + self.args.local_path)
		data = {"kind":"file"}
		data['hash'] = 'sha1:' + get_file_sha1('',self.args.local_path)
		data['magic_hash'] = 'magic_hash:' + get_file_sha1('Ubuntu One',self.args.local_path)
		data = json.dumps(data)
		resp = self.__put('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + remote_path,str(data))
		result = json.loads(resp)
		if result.has_key('error'):
			print('can\'t magic upload')
		else:
			print('magic upload success, file path is ' + result['path'])
			return

		#reality upload
		print('begin upload ' + self.args.local_path)
		mime = guess_type(self.args.local_path)
		if not mime or not mime[0]:
			mime = "text/plain"
		else:
			mime = mime[0]
		resp = self.__put('https://files.one.ubuntu.com/content/~/Ubuntu%20One' + remote_path,open(self.args.local_path),mime)
		try:
			result = json.loads(resp)
		except:
			print('remote path unlegal')
			return
		if result.has_key('error'):
			print('upload failed: ' + result['error'])
		else:
			print('upload success: ' + result['path'])	

	def __delete(self):
		if not self.__check_auth():
			return
		
		resp = self.__delete('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + self.args.remote)
		try:
			result = json.loads(resp)
			if result.has_key('error'):
				print('delete failed: ' + result['error'])
		except:
			print('delete success')

	def __mkdir(self):
		if not self.__check_auth():
			return
		
		resp = self.__put('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + self.args.dir,'{"kind":"directory"}')
		result = json.loads(resp)
		if result.has_key('path'):
			print('create directory success, it path is ' + result['path'])

	def __move(self):
		if not self.__check_auth():
			return
		
		resp = self.__put('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + self.args.from_path,'{"path":"' + self.args.to_path + '"}')
		result = json.loads(resp)
		if result.has_key('error'):
			print('move failed: ' + result['error'])
		else:
			print('move success')

	def __copy(self):
		print('Ubuntu One has not the api')

	def __share(self):
		if not self.__check_auth():
			return

		if self.args.list:
			resp = self.__get('https://one.ubuntu.com/api/file_storage/v1/public_files')
			result = json.loads(resp)
			for item in result:
				print('%45s    %s'%(item['public_url'],item['path']))

		elif self.args.share:
			resp = self.__put('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + self.args.share,'{"is_public":true}')
			result = json.loads(resp)
			if result.has_key('error'):
				print('public failed:' + result['error'])
			else:
				print('public success, public_url is ' + result['public_url'])
		elif self.args.cancel:
			resp = self.__put('https://one.ubuntu.com/api/file_storage/v1/~/Ubuntu%20One' + self.args.cancel,'{"is_public":false}')
			result = json.loads(resp)
			if result.has_key('error'):
				print('cancel public failed:' + result['error'])
			else:
				print('cancel public success, login then you can access it with url https://files.one.ubuntu.com/' + result['key'])
		else:
			print('input -h optional to see how to use')

def to_human_see(bytes_size):
	bytes_size = bytes_size * 1.0
	if bytes_size < 1024.0:
		return str("%.2fByte"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fKB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fMB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fGB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fTB"%bytes_size)
	bytes_size = bytes_size / 1024.0
	if bytes_size < 1024.0:
		return str("%.2fPB"%bytes_size)

	return str("%.2fPB"%bytes_size)

def get_file_sha1(pre_data,filename):
	m = hashlib.sha1()
	f = open(filename)
	is_first = True
	while True:
		data = f.read(10240)
		if not data:
			break
		if is_first:
			is_first = False
			m.update(pre_data)
		m.update(data)
	return m.hexdigest()


if __name__ == '__main__':
	parser = argparse.ArgumentParser(version='1.0',description='It is a command-line tool to operate ubuntu one')
	subparsers = parser.add_subparsers(title='sub-commands',dest='command')

	# auth
	auth_parser = subparsers.add_parser('auth',help='authorize to access your account')

	# quota 
	info_parser = subparsers.add_parser('quota',help='quota info')

	# list
	list_parser = subparsers.add_parser('list',help='list file of the directory')
	list_parser.add_argument('-d',dest='dir_path',metavar='dir_path',help='directory to list')

	# download
	download_parser = subparsers.add_parser('download',help='download file from ubuntu one and output to screen')
	download_parser.add_argument('remote_path',metavar='remote_path',help='which to download')

	# upload
	upload_parser = subparsers.add_parser('upload',help='upload file to ubuntu one')
	upload_parser.add_argument('-r',dest='remote_path',metavar='remote_path',help='where to save')
	upload_parser.add_argument('local_path',metavar='local_path',help='which to upload')

	# delete
	delete_parser = subparsers.add_parser('delete',help='delete file from ubuntu one')
	delete_parser.add_argument('remote',metavar='remote_path',help='which remote file or directory to delete')

	# mkdir
	mkdir_parser = subparsers.add_parser('mkdir',help='create directory')
	mkdir_parser.add_argument('dir',metavar='dir_path',help='where directory to create')

	# move
	move_parser = subparsers.add_parser('move',help='move file')
	move_parser.add_argument('from_path',metavar='from_path',help='src file path')
	move_parser.add_argument('to_path',metavar='to_path',help='dest file path')

	# copy
	copy_parser = subparsers.add_parser('copy',help='copy file')
	copy_parser.add_argument('from_path',metavar='from_path',help='src file path')
	copy_parser.add_argument('to_path',metavar='to_path',help='dest file path')

	# share
	share_parser = subparsers.add_parser('share',help='share or cancel share file,list share file')
	group = share_parser.add_mutually_exclusive_group()
	group.add_argument('-l','--list',dest='list',action='store_true',help='list all public file')
	group.add_argument('-s',dest='share',metavar='file_path',help='which file to share')
	group.add_argument('-c',dest='cancel',metavar='file_path',help='which file to cancel share')

	if len(sys.argv) > 1:
		args = parser.parse_args()
	else:
		parser.print_help()
		parser.exit()

	ubutunone = UbuntuOne(args)
	try:
		ubutunone.run()
	except urllib2.HTTPError,e:
		if e.code == 401 and e.reason == 'UNAUTHORIZED':
			print('please authorize first')
		else:
			print('execute failed, code: ' + str(e.code) + ', reason: ' + e.reason)

