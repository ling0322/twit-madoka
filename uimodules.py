# -*- coding: utf-8 -*-
'''
Created on Jun 18, 2011

@author: ling0322
'''
import tornado.web
import re
import datetime
import time

def _strftime(timestr):
    ''' 将一个标准格式时间, 改变成Tweet上显示的格式 '''

    cntTime = datetime.datetime(*time.gmtime()[0:6])
    t = datetime.datetime(*time.strptime(timestr, "%a %b %d %X %Z %Y")[0:6])
    delta = int((cntTime - t).total_seconds())
    ret = ''
    if t.year != cntTime.year:
        
        # 如果年份不一样，则把年份显示出来
        return t.strftime("%d %b %Y")
        
        
    if delta > 24 * 60 * 60:
        # if interval is more than 1 day then just return the date
        return t.strftime("%d %b")
    else:
        # in other case, return the interval
        if delta / 3600 > 0:
            ret = ret + str(delta / 3600) + 'hr'
            delta = delta % 3600
        elif delta / 60 > 0:
            ret = ret + str(delta / 60) + 'min'
            delta = delta % 60
        else:
            ret = ret + str(delta) + 's'
            
        ret += ' ago'
        return ret

class Entry(tornado.web.UIModule):
    def __init__(self, *args, **kwargs):
        self.re_screen_name = re.compile('@([A-Za-z0-9_]+)')
        tornado.web.UIModule.__init__(self, *args, **kwargs)
    

    
    def render(self, status, screen_name, non_operation = False):
        
        if screen_name == status['screen_name']:
            disp_remove = True
        else:
            disp_remove = False
        
        # 把推中的一些内容改成链接形式
        
        def screen_name_match(match):
            return '<a href="/user/{0}">@{0}</a>'.format(match.group(1))
        status['text'] = self.re_screen_name.sub(screen_name_match, status['text'])
        for url in status['urls']:
            status['text'] = status['text'].replace(
                url['url'], 
                '<a href="{0}">{1}</a>'.format(url['expanded_url'], url['display_url']))
        status['screen_name'] = '<a href="/user/{0}">@{0}</a>'.format(status['screen_name'])
        
        # 把时间改编成距离当前的时间
        
        status['created_at'] = _strftime(status['created_at'])
        
        return self.render_string(
            "status.html", status = status, disp_remove = disp_remove, non_operation = non_operation)
        
class TweetList(tornado.web.UIModule):
    def render(self, screen_name, tweets):
        return self.render_string("tweet_list.html", screen_name = screen_name, tweets = tweets)
    
class Menu(tornado.web.UIModule):
    def render(self, screen_name):
        return self.render_string("menu.html", screen_name = screen_name)

class UserInfo(tornado.web.UIModule):
    def render(self, user_info, screen_name):
        user_info['created_at'] = _strftime(user_info['created_at'])
        return self.render_string("user_info.html", user_info = user_info, screen_name = screen_name)