# -*- coding: utf-8 -*-
 
 
#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import sys 
reload(sys) 
sys.setdefaultencoding('utf-8') 

import logging
import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import os.path
import uuid
import TwitterClient
import base64
import urllib
import re
import getopt
import uimodules

from tornado.options import define, options

twitter_consumer_key = ''
twitter_consumer_secret = ''

# get command line arguments

define("port", default=3322, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/api/(.*)", TwitterClient.TwitterClient),
            (r"/mention", MentionHandler),
            (r"/update", UpdateHandler),
            (r"/retweet", RetweetHandler),
            (r"/login", LoginHandler),
            (r"/twitsignin", TwitterClient.TwitterSignInHandler),
            (r"/logout", LogoutHandler),
            (r"/user/(.*)", UserHandler),
        ]
        settings = dict(
            ui_modules = uimodules,
            login_url = "/login",
            host_url = 'http://loliloli.info/',
            twitter_consumer_key = "cFDUg6a9DU08rPQTukw2w",
            twitter_consumer_secret = "gxDykjVceNppTow1LppvXTrUWNjwIOFvhnf0Imy6NQ0",
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            template_path = os.path.join(os.path.dirname(__file__), "templates"),
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            api_url = 'http://loliloli.info/api',
        )
        tornado.web.Application.__init__(self, handlers, **settings)

class MadokaBaseHandler(tornado.web.RequestHandler):
    def _render_tweets(self, title, page, response):
        if response.error:
            raise tornado.web.HTTPError(403)
            
        tweets = tornado.escape.json_decode(response.body)
        self.render("madoka.html", tweets = tweets, page = page, title = title, 
                    screen_name = self.current_user['screen_name'])
    
    def get_current_user(self):
        if self.get_secure_cookie("access_token") == None:
            return None
        else:
            return tornado.escape.json_decode(self.get_secure_cookie("access_token"))


    
class MainHandler(MadokaBaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous 
    def get(self):
        
        page = self.get_argument('page', 1)
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            page = page,
            access_token = access_token,
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(
            self.settings['api_url'] + '/home_timeline?' + urllib.urlencode(args), 
            self.async_callback(self._render_tweets, 'Timeline', int(page))
            )

class UserHandler(MadokaBaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous 
    def get(self, screen_name):
        
        page = self.get_argument('page', 1)
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            screen_name = screen_name,
            page = page,
            access_token = access_token,
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(
            self.settings['api_url'] + '/user_timeline?' + urllib.urlencode(args), 
            self.async_callback(self._render_tweets, 'Timeline', int(page))
            )   
           
class MentionHandler(MadokaBaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous 
    def get(self):
        access_token = self.get_secure_cookie('access_token')
        page = self.get_argument('page', 1)
        args = dict(
            page = page,
            access_token = access_token,
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(
            self.settings['api_url'] + '/mentions?' + urllib.urlencode(args),
            self.async_callback(self._render_tweets, 'Mention', int(page))
            )
        
        return  


class UpdateHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        def on_response(response):
            if response.error:
                raise tornado.web.HTTPError(403)
            self.redirect('/')
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
        )
        post_args = dict(
            status = tornado.escape.url_escape(self.get_argument('madoka'))
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/update?' + urllib.urlencode(args), 
                   method = 'POST',
                   body = urllib.urlencode(post_args),
                   callback = on_response)

class RetweetHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        
        def on_response(response):
            if response.error:
                raise tornado.web.HTTPError(403)
            
            tweet = tornado.escape.json_decode(response.body)
            self.render("retweet.html", screen_name = self.current_user['screen_name'],
                        text = 'RT @' + tweet['screen_name'] + ':' + tweet['text'])
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
            id = self.get_argument('id')
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/show?' + urllib.urlencode(args), on_response)
        
        
class LoginHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("access_token", None):
            self.set_secure_cookie('access_token', self.get_argument("access_token"))
            self.redirect('/')
            self.finish()
            return
        
        self.redirect('/twitsignin?callback=' + tornado.escape.url_escape('http://' + self.request.host + '/login'))

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect('/')


def main():
    # tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
