# coding: utf-8

import web

from setting import render

from accountHandler import AcountHandler

class PrivateHandler(AcountHandler):
    def write_html(self, user=None):
        return render.private_entry(user=user)

    def GET(self):
        user = self.valid()
        if user:
            return self.write_html(user)
        else:
            self.redirect('/login')

    def POST(self):
        user = self.valid()

        if user:
            i = web.input()
