# -*- coding: utf-8 -*-
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))
from Seed import Seed

class WindowsOS(Seed):

    def __init__(self, browser):
        Seed.__init__(self, browser)
        try:
            self.browser_version = self.resources.split('Application\\')[1].split('\\')[0]
        except:
            self.browser_version = ""
