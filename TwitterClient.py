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
    def _on_access_token(self, callback, response):
        ''' STEP8(最后一步): 得到access_token (终于完成了ww '''
        
        if response.error:
            raise tornado.web.HTTPError(403, "Get Access Token Failed ~")
            return

        access_token = tornado.auth._oauth_parse_response(response.body)

        
        url = tornado.escape.url_unescape(self.get_cookie('_tcallback_url').encode('utf-8'))
        self.clear_cookie('_tcallback_url')
        self.redirect(url + '?access_token=' + tornado.escape.json_encode(access_token))
        
    def _on_request_token(self, authorize_url, callback_uri, response):
        '''
        STEP2:
        这个函数得到oauth_token以后触发，在原来的实现中主要完成重定向到authenticate页面的任务
        在我们这里则是用自己的登录框去替代Twitter官方的登录界面
        '''
        
        def on_authenticate_page(response):
            if response.error:
                raise tornado.web.HTTPError(403, "Get Authenticate Message Failed ~")
            
            # STEP3: 从authenticate_page里面得到authenticity_token和oauth_token, 生成登录界面
            
            authenticity_token = re.findall('<input name=\"authenticity_token\" type=\"hidden\" value=\"(.+)\" \/>', response.body)[0]
            oauth_token = re.findall('<input id=\"oauth_token\" name=\"oauth_token\" type=\"hidden\" value=\"(.+)\" \/>', response.body)[0]
            
            self.render("login.html", 
                authenticity_token = authenticity_token,
                oauth_token = oauth_token,
                authorize_url = self.request.full_url())
        
        
        if response.error:
            raise tornado.web.HTTPError(403, "Could not get request token ~")
        request_token = tornado.auth._oauth_parse_response(response.body)
        data = "|".join([base64.b64encode(request_token["key"]),
            base64.b64encode(request_token["secret"])])
        self.set_cookie("_oauth_request_token", data)
        args = dict(oauth_token=request_token["key"])
        if callback_uri:
            args["oauth_callback"] = urlparse.urljoin(
                self.request.full_url(), callback_uri)
        auth_url = authorize_url + "?" + urllib.urlencode(args)
        
        # self.redirect(auth_url) <- 原本在这里的是这个
        # 接着要去GET这个页面，因为我们还要得到里面的authenticity_token
        
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch(auth_url, on_authenticate_page)
        
    
    @tornado.web.asynchronous 
    def get(self):
        
        def null_func():
            pass
        
        if self.get_argument("oauth_token", None):
            
            # STEP7: 使用get_authenticated_user函数来根据oauth_token和oauth_verifier得到用户的access_token
            # 这里用随意用了一个null_func，因为这个callback函数在我们这里不需要
            
            self.get_authenticated_user(null_func)
            return
        
        # STEP1: 使用TwitterMixin自带的功能得到oauth_token
        
        callback_url = self.get_argument('callback')
        self.set_cookie('_tcallback_url', callback_url)
        self.authenticate_redirect()
        
    @tornado.web.asynchronous 
    def post(self):
        ''' 
        STEP4: 当用户输入用户名和密码提交的时候触发这个函数, 
        将用户的用户名密码信息POST到https://api.twitter.com/oauth/authorize以后抓取转到的页面
        提取相关参数
        '''

        
        def on_authorize_page(response):
            ''' STEP5: 得到oauth_token和oauth_verifier然后重定向去调用get_authenticated_user函数 '''
            
            if response.error:
                raise tornado.web.HTTPError(403, "Authorize Failed ~")
            
            # 如果成功，可以在返回的页面里面扣到oauth_token和oauth_verifier
            
            try:
                token = re.findall('<meta http-equiv=\"refresh\" content=\"0;url=.+oauth_token=(.+)&oauth_verifier=(.+)\".*>', response.body)
                oauth_token = token[0][0]
                oauth_verifier = token[0][1]
            except:
                raise tornado.web.HTTPError(403, "Get Authorize Message Failed ~")
            
            # 接着要使用TwitterMixin自带的函数来验证oauth_token得到access_token, 所以这里要重定向到callback_url
            
            args = dict(
                oauth_token = oauth_token,
                oauth_verifier = oauth_verifier,
            )
            
            self.redirect(self.request.full_url() + '?' + urllib.urlencode(args))

        
        args = {
            'authenticity_token': self.get_argument('authenticity_token'),
            'oauth_token': self.get_argument('oauth_token'),
            'session[username_or_email]': self.get_argument('user'),
            'session[password]': self.get_argument('password'),
        }
        http = tornado.httpclient.AsyncHTTPClient()
        http.fetch('https://api.twitter.com/oauth/authorize', 
                   method = 'POST',
                   body = urllib.urlencode(args),
                   callback = on_authorize_page)
        


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
        elif request == 'test':
            #得到某个特定id的Tweet

            self.twitter_request(
                path = "/related_results/show/" + str(self.get_argument('id')),
                access_token = {u'secret': secret, u'key': key},
                callback = self.async_callback(self._on_fetch, single_tweet = True),
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

            self.twitter_request(
                path = "/statuses/update",
                post_args={"status": text},
                access_token = {u'secret': secret, u'key': key},
                callback = on_fetch,
                )       
            
    
