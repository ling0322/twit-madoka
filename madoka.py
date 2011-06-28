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
import time

from tornado.options import define, options

twitter_consumer_key = ''
twitter_consumer_secret = ''

# get command line arguments

define("port", default=3322, help="run on the given port", type=int)

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/api/access_token", TwitterClient.TwitterSignInHandler),
            (r"/api/(.*)", TwitterClient.TwitterClient),
            (r"/mention", MentionHandler),
            (r"/update", UpdateHandler),
            (r"/retweet", RetweetHandler),
            (r"/login", LoginHandler),

            (r"/logout", LogoutHandler),
            (r"/user/(.*)", UserHandler),
            (r"/remove", RemoveHandler),
            (r"/conversation_line", ConversationLineHandler),
            (r"/reply", ReplyHandler),
        ]
        settings = dict(
            ui_modules = uimodules,
            login_url = "/login",
            twitter_consumer_key = "cFDUg6a9DU08rPQTukw2w",
            twitter_consumer_secret = "gxDykjVceNppTow1LppvXTrUWNjwIOFvhnf0Imy6NQ0",
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            template_path = os.path.join(os.path.dirname(__file__), "templates"),
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            api_url = 'http://127.0.0.1:3322/api',
        )
        tornado.web.Application.__init__(self, handlers, **settings)

class MadokaBaseHandler(tornado.web.RequestHandler):
    def _response_check(self, response, raise_exception = True):
        ''' 
        检查是否返回错误，
        raise_exception为真, 则有错误抛出异常，没有错误就正常返回
        raise_exception为假, 则有错误返回False，没有错误就返回True
        '''
        if raise_exception == True:
            if response.error:
                raise tornado.web.HTTPError(403)
        else:
            if response.error:
                return False
            else:
                return True          
        
    def _render_tweets(self, title, page, response):
        self._response_check(response)
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

class RemoveHandler(MadokaBaseHandler):
    @tornado.web.authenticated
    @tornado.web.asynchronous 
    def get(self):
        
        # 删除一条Tweet，首先让用户确认是否删除
        
        def on_response(response):
            self._response_check(response)
            tweet = tornado.escape.json_decode(response.body)
            self.render('remove.html', tweet = tweet, id = id, 
                        screen_name = self.current_user['screen_name'])
            
        access_token = self.get_secure_cookie('access_token')
        id = self.get_argument('id')
        
        args = dict(
            id = id,
            access_token = access_token,
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(
            self.settings['api_url'] + '/show?' + urllib.urlencode(args),
            on_response
            )
        
    @tornado.web.authenticated
    @tornado.web.asynchronous         
    def post(self):
        
        # 用户确认后删除这条推
        
        def on_response(response):
            self._response_check(response)
            self.redirect('/')
        
        access_token = self.get_secure_cookie('access_token')
        id = self.get_argument('id')
        
        args = dict(
            id = id,
            access_token = access_token,
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(
            self.settings['api_url'] + '/remove?' + urllib.urlencode(args),
            on_response
            )
        

class UpdateHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        def on_response(response):
            self._response_check(response)
            self.redirect('/')
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
        )
        
        # 如果有in_reply_to则加入in_reply_to参数
        
        if self.get_argument('in_reply_to', None):
            args['in_reply_to'] = self.get_argument('in_reply_to', None)
            
        post_args = dict(
            status = tornado.escape.url_escape(self.get_argument('madoka'))
        )
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/update?' + urllib.urlencode(args), 
                   method = 'POST',
                   body = urllib.urlencode(post_args),
                   callback = on_response)

class ConversationLineHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        
        # 这里要完成三步工作
        #
        #     1. 得到原始推的内容
        #     2. 得到相关推的内容
        #     3. *得到原始推in_reply_to推的内容
        #
        # 因为Twitter API -> /related_results/show/:id在有些时候并不能返回会话
        # 所以还需要调用得到in_reply_to的推的内容 ( 参照现在Twitter官方Web的方法
        # 要等到三块内容都完成的时候才会产生输出
        # 因为Tornado是单线程运行的 所以我们不需要考虑临界条件的问题ww
        
        closure_var = {}
        closure_var['finished_one'] = False
        closure_var['in_reply_to_finished'] = False
        
        def _on_related_results(response):
            
            # 这里忽略错误
            
            if self._response_check(response, raise_exception = False) == True:
                closure_var['related_results'] = tornado.escape.json_decode(response.body)
            else:
                closure_var['related_results'] = dict(
                    in_reply_to = [],
                    replies = [],
                    )
                 
            request_finished()

            
        def _on_origin_tweet(response):
            self._response_check(response)
            closure_var['origin_tweet'] = tornado.escape.json_decode(response.body)
            request_finished()

            
        def _on_in_reply_to(response):
            
            # 这里可以忽略错误
            
            if self._response_check(response, raise_exception = False) == True:
                closure_var['related_results']['in_reply_to'].append(tornado.escape.json_decode(response.body))
                
            closure_var['in_reply_to_finished'] = True
            request_finished()            
            
            pass
            
        def request_finished():
            if closure_var['finished_one'] == False:
                closure_var['finished_one'] = True
                return 
            
            # 如果原始推有in_reply_to对象, 且related_results没有返回in_reply_to的推那么就再去
            # 调用API得到in_reply_to的推
            
            not_finished = closure_var['in_reply_to_finished'] == False
            origin_has_reply_to = closure_var['origin_tweet']['in_reply_to_status_id'] != None
            empty_in_reply_to = len(closure_var['related_results']['in_reply_to']) == 0
            
            if not_finished and origin_has_reply_to and empty_in_reply_to:
                args = dict(
                    access_token = access_token,
                    id = closure_var['origin_tweet']['in_reply_to_status_id'],
                    )
                http.fetch(self.settings['api_url'] + '/show?' + urllib.urlencode(args), _on_in_reply_to)
                return 

            self.render(
                "conversation_line.html", 
                related_results = closure_var['related_results'],
                origin_tweet = closure_var['origin_tweet'],
                screen_name = self.current_user['screen_name'],
                )
                
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
            id = self.get_argument('id')
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/details?' + urllib.urlencode(args), _on_related_results)
        http.fetch(self.settings['api_url'] + '/show?' + urllib.urlencode(args), _on_origin_tweet)

        
class ReplyHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        
        def on_response(response):
            self._response_check(response)
            tweet = tornado.escape.json_decode(response.body)
            user_mentions = re.findall('@[A-Za-z0-9]+', tweet['text'])
            mentions = []
            for mention in user_mentions:
                
                # 回复列表里面去掉用户自己, 去掉前面已经提到过的
                
                if mention == '@' + self.current_user['screen_name']:
                    continue
                elif mention in mentions:
                    continue
                
                mentions.append(mention)
                
            self.render(
                "retweet.html", 
                screen_name = self.current_user['screen_name'],
                text = '@' + tweet['screen_name'] + ' ' + ' '.join(mentions),
                origin_tweet = tweet,
                title = 'Reply',
                )
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
            id = self.get_argument('id')
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/show?' + urllib.urlencode(args), on_response)


class RetweetHandler(MadokaBaseHandler): 
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        
        def on_response(response):
            self._response_check(response)
            tweet = tornado.escape.json_decode(response.body)
            self.render(
                "retweet.html", 
                screen_name = self.current_user['screen_name'],
                text = 'RT @' + tweet['screen_name'] + ': ' + tweet['text'],
                origin_tweet = tweet,
                title = 'Retweet',
                )
            
        access_token = self.get_secure_cookie('access_token')
        args = dict(
            access_token = access_token,
            id = self.get_argument('id')
        )
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/show?' + urllib.urlencode(args), on_response)
        
        
class LoginHandler(tornado.web.RequestHandler):

    def initialize(self):
        print "gggggggggggg"

    def get(self):
        self.render('login.html', failed = self.get_argument('failed', 'false'))
    
    def _on_access_token(self, response):
        if response.error:
            
            # 401返回值表示用户名/密码错误
            
            if response.code == 401:
                self.redirect('login?failed=true')
            else:
                raise tornado.web.HTTPError(403)
        
        self.set_secure_cookie('access_token', response.body)
        self.redirect('/')
        
    
    @tornado.web.asynchronous    
    def post(self):

        post_args = dict(
            user = self.get_argument('user'),
            passwd = self.get_argument('passwd'),
        )
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self.settings['api_url'] + '/access_token', 
                   method = 'POST',
                   body = urllib.urlencode(post_args),
                   callback = self._on_access_token)
        
        

class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect('/')


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
