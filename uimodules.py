# -*- coding: utf-8 -*-
'''
Created on Jun 18, 2011

@author: ling0322
'''
import tornado.web
import re
import datetime
import time

class Entry(tornado.web.UIModule):
    def __init__(self, *args, **kwargs):
        self.re_screen_name = re.compile('@([A-Za-z0-9_]+)')
        self.re_link = re.compile('(https|http)://([-\w]+\.)+[-\w]+(/[-\w./?%&=]*)?')
        tornado.web.UIModule.__init__(self, *args, **kwargs)
    
    def _strftime(self, timestr):
        ''' 将一个标准格式时间, 改变成Tweet上显示的格式 '''

        cntTime = datetime.datetime(*time.gmtime()[0:6])
        t = datetime.datetime(*time.strptime(timestr, "%a %b %d %X %Z %Y")[0:6])
        delta = int((cntTime - t).total_seconds())
        ret = ''
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
    
    def render(self, status, screen_name, non_operation = False):
        
        if screen_name == status['screen_name']:
            disp_remove = True
        else:
            disp_remove = False
        
        # 把推中的一些内容改成链接形式
        
        def screen_name_match(match):
            return '<a href="/user/{0}">@{0}</a>'.format(match.group(1))
        def link_match(match):
            return '<a href="{0}">{0}</a>'.format(match.group(0))
        status['text'] = self.re_screen_name.sub(screen_name_match, status['text'])
        status['text'] = self.re_link.sub(link_match, status['text'])
        status['screen_name'] = '<a href="/user/{0}">@{0}</a>'.format(status['screen_name'])
        
        # 把时间改编成距离当前的时间
        
        status['created_at'] = self._strftime(status['created_at'])
        
        return self.render_string(
            "status.html", status = status, disp_remove = disp_remove, non_operation = non_operation)
        
class TweetList(tornado.web.UIModule):
    def render(self, screen_name, tweets):
        return self.render_string("tweet_list.html", screen_name = screen_name, tweets = tweets)
    
class Menu(tornado.web.UIModule):
    def render(self, screen_name):
        return self.render_string("menu.html", screen_name = screen_name)
