# -*- coding: utf-8 -*-

'''
Created on Jun 18, 2011

@author: ling0322
'''

import tornado.web
import time
import datetime
import urllib
import base64
import re
import tornado.auth

class TwitterSignInHandler(tornado.auth.TwitterMixin, tornado.web.RequestHandler):
    def _on_access_token(self, response):
        ''' STEP5(最后一步): 得到access_token (终于完成了ww '''
        
        if response.error:
            raise tornado.web.HTTPError(403, "Get Access Token Failed ~")
            return

        access_token = tornado.auth._oauth_parse_response(response.body)
        self.write(tornado.escape.json_encode(access_token))
        self.finish()

    def _on_authenticate_page(self, response):
        '''
        STEP3: 
        抓取到Twitter登陆页面以后将用户名和密码POST上去
        '''
        
        if response.error:
            raise tornado.web.HTTPError(403, "Get Authenticate Message Failed ~")
            
        authenticity_token = re.findall('<input name=\"authenticity_token\" type=\"hidden\" value=\"(.+)\" \/>', response.body)[0]
        oauth_token = re.findall('<input id=\"oauth_token\" name=\"oauth_token\" type=\"hidden\" value=\"(.+)\" \/>', response.body)[0]
            
        # 将得到的用户名和密码POST到Twitter登陆界面
            
        args = {
            'authenticity_token': authenticity_token,
            'oauth_token': oauth_token,
            'session[username_or_email]': self.get_argument('user'),
            'session[password]': self.get_argument('passwd'),
        }
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch('https://api.twitter.com/oauth/authorize', 
                    method = 'POST',
                    body = urllib.urlencode(args),
                    callback = self._on_authorize_page)
       
    def _on_request_token(self, authorize_url, callback_uri, response):
        '''
        STEP2:
        用得到的oauth_token去抓取Twitter的登陆界面
        '''

        if response.error:
            raise tornado.web.HTTPError(403, "Could not get request token ~")
        self._request_token = tornado.auth._oauth_parse_response(response.body)
        
        args = dict(oauth_token = self._request_token["key"])
        auth_url = authorize_url + "?" + urllib.urlencode(args)
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(auth_url, self._on_authenticate_page)
        
    def _on_authorize_page(self, response):
        ''' 
        STEP4: 
        如果登陆成功则取得oauth_token和oauth_verifier然后利用auth模块得到access_token
        '''
            
        if response.error:
            raise tornado.web.HTTPError(404, "Authorize Failed ~")
            
        # 如果成功，可以在返回的页面里面扣到oauth_token和oauth_verifier
            
        try:
            token = re.findall('<meta http-equiv=\"refresh\" content=\"0;url=.+oauth_token=(.+)&oauth_verifier=(.+)\".*>', response.body)
            request_key = token[0][0]
            oauth_verifier = token[0][1]
        except:
            raise tornado.web.HTTPError(401, "Get Authorize Message Failed ~")
            
        if self._request_token['key'] != request_key:
            raise tornado.web.HTTPError(403, "Get Access Token Failed ~")
            return
        
        token = dict(
            key = self._request_token['key'], 
            secret = self._request_token['secret'],
            verifier = oauth_verifier
            )
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(self._oauth_access_token_url(token), self._on_access_token)
            
    @tornado.web.asynchronous 
    def post(self):
        ''' 
        STEP1: 
        过程的入口，由tornado的auth模块帮我们得到oauth_token
        '''
        self.authenticate_redirect()

    @tornado.web.asynchronous 
    def get(self):
        ''' 
        STEP1: 
        过程的入口，由tornado的auth模块帮我们得到oauth_token
        '''
        self.authenticate_redirect()
        
class TwitterClient(tornado.auth.TwitterMixin, tornado.web.RequestHandler):
    '''
    A Twitter Client for Madoka frontend
    supported request:
    POST
        update
    GET
        tl
        mention
        show  (得到某个特定id的Tweet
        usertl (User Timeline
        remove
    '''
    
    def _on_twitter_request(self, callback, response):
        
        # 这个也是TwitterMixin里面的东西，重写方法来拦截错误
        if response.error:
            raise response.error
            return
        
        # 如果callback为None表示不需要回调函数，就直接调用self.finish就可以了ww
        if callback != None:
            callback(tornado.escape.json_decode(response.body))
        else:
            self.finish()
            

    def _dumpTweet(self, tweet):
        ''' 整理Tweet的内容将Twitter API返回的Tweet的格式转换成本地使用的格式 '''
        
        t = {}
        t['text'] = tweet['text']
        t['name'] = tweet['user']['name']
        t['screen_name'] = tweet['user']['screen_name']
        t['created_at'] = tweet['created_at'].replace('+0000', 'UTC')
        t['id'] = tweet['id']
        t['in_reply_to_status_id'] = tweet['in_reply_to_status_id']
        return t
    
    
    def _on_fetch(self, tweets, single_tweet = False):
        
        # 重载_on_twitter_request方法以后错误被拦截了，以下代码就不需要了
        # if tweets == None:
        #    raise tornado.httpclient.HTTPError(403)
        
        if single_tweet == False:
            dump = [self._dumpTweet(tweet) for tweet in tweets]
        else:
            dump = self._dumpTweet(tweets)
        self.write(tornado.escape.json_encode(dump))
        self.finish()
        
    def _on_related_results(self, res):
        
        # 处理/related_results/show/:id.json API返回结果
        # 如果有相关结果list就有1个元素 反之则没有
        
        in_reply_to = []
        replies = []
            
        if len(res) > 0:
            results = res[0]['results']
            for item in results:
                if item['annotations']['ConversationRole'] == 'Ancestor':
                    in_reply_to.append(self._dumpTweet(item['value']))
                else:
                    replies.append(self._dumpTweet(item['value']))
        
        dump = dict(
            in_reply_to = in_reply_to,
            replies = replies,
            )
        
        self.write(tornado.escape.json_encode(dump))
        self.finish()
        
    def _dump_user_info(self, user_info):
        ui = {}
        ui['id'] = user_info['id']
        ui['name'] = user_info['name']
        ui['screen_name'] = user_info['screen_name']
        ui['location'] = user_info['location']
        ui['description'] = user_info['description']
        ui['profile_image_url'] = user_info['profile_image_url']
        ui['followers_count'] = user_info['followers_count']
        ui['friends_count'] = user_info['friends_count']
        ui['created_at'] = user_info['created_at'].replace('+0000', 'UTC')
        ui['favourites_count'] = user_info['favourites_count']
        ui['following'] = user_info['following']
        ui['statuses_count'] = user_info['statuses_count']
        return ui
        
    def _on_user_info(self, user_info):
        self.write(tornado.escape.json_encode(self._dump_user_info(user_info)))
        self.finish()
        
    @tornado.web.asynchronous
    def get(self, request):
        access_token = tornado.escape.json_decode(self.get_argument('access_token'))
        secret = access_token['secret']
        key = access_token['key']
        
        if request == 'home_timeline':
            # get home timeline
            
            self.twitter_request(
                path = "/statuses/home_timeline",
                access_token = {u'secret': secret, u'key': key},
                callback = self._on_fetch,
                page = self.get_argument('page', 1),
                )  
        elif request == 'mentions':
            # 得到mention一个用户的Tweet

            self.twitter_request(
                path = "/statuses/mentions",
                page = self.get_argument('page', 1),
                access_token = {u'secret': secret, u'key': key},
                callback = self._on_fetch,
                )  
        elif request == 'show':
            #得到某个特定id的Tweet

            self.twitter_request(
                path = "/statuses/show/" + str(self.get_argument('id')),
                access_token = {u'secret': secret, u'key': key},
                callback = self.async_callback(self._on_fetch, single_tweet = True),
                ) 
        elif request == 'details':
            
            #得到某个特定id的Tweet相关的结果

            self.twitter_request(
                path = "/related_results/show/" + str(self.get_argument('id')),
                access_token = {u'secret': secret, u'key': key},
                callback = self._on_related_results,
                ) 
            
        elif request == 'user_info':
            
            # 得到某个用户的信息
            
            self.twitter_request(
                path = "/users/show",
                access_token = {u'secret': secret, u'key': key},
                callback = self._on_user_info,
                screen_name = self.get_argument('screen_name')
                )             
            
        elif request == 'remove':
            # 删除某个Tweet
            def on_fetch(tweet):
                pass
            
            self.twitter_request(
                path = "/statuses/destroy/" + str(self.get_argument('id')),
                access_token = {u'secret': secret, u'key': key},
                post_args = {},
                callback = None,
                ) 
        elif request == 'user_timeline':
            # 得到某用户的Timeline
            
            self.twitter_request(
                path = "/statuses/user_timeline",
                access_token = {u'secret': secret, u'key': key},
                page = self.get_argument('page', 1),
                screen_name = self.get_argument('screen_name'),
                callback = self._on_fetch,
                ) 
            
            pass
        else:
            raise tornado.httpclient.HTTPError(403, 'Invaild Request Path ~')     
            
    @tornado.web.asynchronous
    def post(self, request):
        access_token = tornado.escape.json_decode(self.get_argument('access_token'))
        secret = access_token['secret']
        key = access_token['key']
        if request == 'update':
            # tweet
            
            status = tornado.escape.url_unescape(self.get_argument('status').encode('utf-8'))
            def on_fetch(tweets):
                if tweets == None:
                    raise tornado.httpclient.HTTPError(403)
                self.write('Done ~')
                self.finish()
            
            # 将多于140个字符的部分截去
            
            if len(status) > 140:
                text = status[:136] + '...'
            else:
                text = status

            # 如果有in_reply_to参数则带上这个参数ww
            
            in_reply_to_param = {}
            if self.get_argument('in_reply_to', None):
                in_reply_to_param['in_reply_to_status_id'] = self.get_argument('in_reply_to', None)
            
            self.twitter_request(
                path = "/statuses/update",
                post_args={"status": text},
                access_token = {u'secret': secret, u'key': key},
                callback = on_fetch,
                **in_reply_to_param
                )       
            
    
