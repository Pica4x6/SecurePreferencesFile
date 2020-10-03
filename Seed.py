import struct, getpass, os, json, sys
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))
import subprocess
from sys import platform
from colorama import Fore
from collections import OrderedDict
from utils import calculateHMAC, change_spf
import re

class Browser(object):
    def __init__(self, user,  browser="Chrome"):
        options = {}
        if platform == "linux" or platform == "linux2":
            # linux
            options['Edge'] = {'resources_path': '',
                               'spf_path': '',
                               'expected_seed': b''}
            options['Chrome'] = {'resources_path': '/opt/google/chrome',
                                 'spf_path': '/home/{}/.config/google-chrome/Default/Preferences'.format(user),
                                 'expected_seed': b''}
            options['Brave'] = {
                'resources_path': '',
                'spf_path': '',
                'expected_seed': b''}

            options['Opera'] = {
                'resources_path': '',
                'spf_path': '',
                'expected_seed': b''}

        elif platform == "darwin":
            # OS X
            options['Chromium'] = {'resources_path': '/Users/{}/Downloads/chrome-mac/Chromium.app/Contents'.format(user),
                                 'spf_path': '/Users/{}/Library/Application Support/Chromium/Default/Secure Preferences'.format(
                                     user),
                                 'expected_seed': b''}
            options['Edge'] = {'resources_path': '/Applications/Microsoft Edge.app/Contents/',
                               'spf_path': '/Users/{}/Library/Application Support/Microsoft Edge/Default/Secure Preferences'.format(user),
                               'expected_seed': b''}
            options['Opera'] = {'resources_path': '/Applications/Opera.app/Contents/',
                               'spf_path': '/Users/{}/Library/Application Support/com.operasoftware.Opera/Secure Preferences'.format(
                                   user),
                               'expected_seed': b''}
            options['Chrome'] = {'resources_path': '/Applications/Google Chrome.app/Contents/',
                                 'spf_path': '/Users/{}/Library/Application Support/Google/Chrome/Default/Secure Preferences'.format(user),
                                 'expected_seed': b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'}
            options['Brave'] = {
                'resources_path': '/Applications/Brave Browser.app/Contents/',
                'spf_path': '/Users/{}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Secure Preferences'.format(user),
                'expected_seed': b''}

        elif platform == "win32":
            architectures = [" (x86)", ""]
            
            options['Edge'] = {'resources_path': 'C:\\Program Files{}\\Microsoft\\Edge\\Application',
                                'spf_path': 'C:\\Users\\' + user + '\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Secure Preferences',
                               'expected_seed':b''}
            options['Chrome'] = {'resources_path':'C:\\Program Files{}\\Google\\Chrome\\Application',
                                 'spf_path':'C:\\Users\\'+user+'\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Secure Preferences',
                                 'expected_seed': b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'}
            options['Brave'] = {'resources_path': 'C:\\Program Files{}\\BraveSoftware\\Brave-Browser\\Application',
                                 'spf_path': 'C:\\Users\\' + user + '\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Secure Preferences',
                                'expected_seed':b''}
            options['Chromium'] = {'resources_path': 'C:\\Users\\' + user + '\\AppData\\Local\\Chromium\\Application',
                                 'spf_path': 'C:\\Users\\' + user + '\\AppData\\Local\\Chromium\\User Data\\Default\\Secure Preferences',
                                 'expected_seed': b''}
            options['Opera'] = {'resources_path': 'C:\\Users\\' + user + '\\AppData\\Local\\Programs\\Opera',
                                   'spf_path': 'C:\\Users\\' + user + '\\AppData\\Roaming\\Opera Software\\Opera Stable\\Secure Preferences',
                                   'expected_seed': b''}
            
            for browser in ['Edge', 'Chrome', 'Brave']:
                for architecture in architectures:
                    if os.path.isdir(options[browser]['resources_path'].format(architecture)):
                        options[browser]['resources_path'] = options[browser]['resources_path'].format(architecture)


        if browser in options.keys():
            self.options = options[browser]
        else:
            # If we want to check resources.pak from a fixed path
            self.options = {'spf_path':browser}

    def get_spf(self):
        return self.options['spf_path']

    def get_resources_path(self):
        return self.options['resources_path']

    def get_expected_seed(self):
        return self.options['expected_seed']


class Seed():
    
    def __init__(self, browser):
        self.user = getpass.getuser()
        self.browser = Browser(self.user, browser)
        self.expected_seed = self.browser.get_expected_seed()
        self.resources = self.find_resources(self.browser.get_resources_path())
        if self.resources:
            try:
                self.browser_version = self.resources.split('Versions/')[1].split(os.sep)[0]
            except:
                self.browser_version = ""
        else:
            print('{} Path NOT found!{}'.format(Fore.RED, Fore.RESET))
            sys.exit()

    def find_resources(self, resources_path):
        found = False
        filename = False
        for dirpath, dirnames, filenames in os.walk(resources_path):
            for filename in filenames:
                if filename in ["resources.pak", "opera.pak"]:
                    filename = os.path.join(dirpath, filename)
                    found = True
                    break
            if (found):
                break
        if (not found):
            # TODO:Look for that file in another path
            pass
        return filename
    
    def get_seed(self):
        seed = ''
        with open(self.resources, 'rb') as f:
            data = f.read()

        # Gets the version, encoding, number of resources and alias count of the resources.pak file
        encoding, resource_count, alias_count = struct.unpack('<BxxxHH', data[4:12])
        header_size = 12
        resourceSize = 2 + 4

        # Helper function to unpack the resources
        def entry_at_index(idx):
            offset = header_size + idx * resourceSize
            return struct.unpack('<HI', data[offset:offset + resourceSize])

        # Finds the seed
        outputs = []
        prev_resource_id, prev_offset = entry_at_index(0)
        for i in range(1, resource_count + 1):
            resource_id, offset = entry_at_index(i)
        
            if (offset - prev_offset == 64):
                seed = data[prev_offset:offset]
                # print(seed.decode("ISO-8859-1"))
                # return seed
            outputs.append(data[prev_offset:offset])
            prev_resource_id, prev_offset = resource_id, offset

        self.seed = seed

        return outputs

    def get_resources(self):
    
        with open(self.resources, 'rb') as f:
            data = f.read()
    
        # Gets the version, encoding, number of resources and alias count of the resources.pak file
        encoding, resource_count, alias_count = struct.unpack('<BxxxHH', data[4:12])
        header_size = 12
        resourceSize = 2 + 4
    
        # Helper function to unpack the resources
        def entry_at_index(idx):
            offset = header_size + idx * resourceSize
            return struct.unpack('<HI', data[offset:offset + resourceSize])
    
        # Finds the seed
        outputs = []
        prev_resource_id, prev_offset = entry_at_index(0)
        for i in range(1, resource_count + 1):
            resource_id, offset = entry_at_index(i)

            outputs.append(data[prev_offset:offset])
            prev_resource_id, prev_offset = resource_id, offset
        return outputs

    def __HMAChelper(self, macs, value, path, arg, sid, seed, extension=False):
        if isinstance(value, OrderedDict):
            if (arg[0] in value):
                if arg[0] in macs:
                    path += arg[0] + "."
                    macs = self.__HMAChelper(macs[arg[0]], value[arg[0]], path, arg[1:], sid, seed)
                else:
                    if not extension:
                        macs = self.__HMAChelper(macs, value[arg[0]], path, arg[1:], sid, seed, extension=value)
                    else:
                        macs = self.__HMAChelper(macs, value[arg[0]], path, arg[1:], sid, seed, extension)
                return macs
            else:
                if len(arg) > 2:
                    self.__HMAChelper(macs, value[arg[0]], path, arg[1:], sid, seed)
                elif len(arg) == 2:
                    if arg[0] in value:
                        path += arg[0] + "."
                        before = macs
                        macs = calculateHMAC(value[arg[0]], path[:-1], sid, seed)
                else:
                    before = macs
                    macs = calculateHMAC(value, path[:-1], sid, seed)
                if before == macs:
                    return seed
                else:
                    return macs
                # return macs
        else:
            before = macs
            if extension:
                value = extension
            macs = calculateHMAC(value, path[:-1], sid, seed)
            if before == macs:
                return seed
            else:
                return macs
        # return macs
    
    
    def look_for_seed(self, resources):
        
        try:
            # # Windows
            sid = subprocess.check_output(['wmic', 'useraccount', 'where', 'name=\'' + self.user + '\'', 'get', 'sid'],
                                          universal_newlines=True)
            sid = sid.replace('\n', '').replace('SID', '').replace(' ', '')[:-5]
        except:
            # Mac
            try:
                sid = subprocess.check_output(['system_profiler', 'SPHardwareDataType', '|', 'awk', '\'/UUID/ { print $3; }\''],
                                              universal_newlines=True)
                found = re.search('Hardware UUID: (.*)', sid)  # .group(1)
                sid = found.group(1)
            except:
                sid = subprocess.check_output(['blkid'], universal_newlines=True)
                sid = sid.split("\n")
                elem = sid[1]
                found = re.findall(r' UUID=\"(.+?)\"', elem)  # .group(1)
                if found:
                    sid = found[0]
                    
        with open(self.browser.get_spf(), encoding="utf-8") as json_data:
            data = json.load(json_data, object_pairs_hook=OrderedDict)
        temp = OrderedDict(sorted(data.items()))
        data = temp
        
        to_change = ""
        if 'browser' in temp.keys():
            # Chrome and Brave
            to_change += 'browser'
            if 'show_home_button' in temp['browser'].keys():
                to_change += '%show_home_button%{}'.format(temp['browser']['show_home_button'])
        elif 'homepage_is_newtabpage' in temp.keys():
            # Edge
            to_change += 'homepage_is_newtabpage%{}'.format(temp['homepage_is_newtabpage'])
        
        elif 'vpn' in temp.keys():
            # Opera
            to_change += 'vpn'
            if 'last_established_location' in temp['vpn'].keys():
                to_change += '%{}%{}'.format('last_established_location', temp['vpn']['last_established_location'])

        if not to_change:
            if 'extensions' in temp.keys():
                to_change += 'extensions'
                if 'settings' in temp['extensions'].keys():
                    to_change += '%settings'
                    extension = list(temp['extensions']['settings'].keys())[0]
                    if 'state' in temp['extensions']['settings'][extension].keys():
                        to_change += '%{}%state%{}'.format(extension,temp['extensions']['settings'][extension]['state'])
        
        for resource in resources:
            seed = self.__HMAChelper(data['protection']['macs'], data, "", to_change.split('%'), sid, resource)
            if type(seed)==bytes:
                break
        
        if type(seed)!=bytes:
            #Try blank: b''
            # print("Trying empty resource...")
            resource = b''
            seed = self.__HMAChelper(data['protection']['macs'], data, "", to_change.split('%'), sid, resource)
            if type(seed) != bytes:
                return False
        
        print('{}\t If we modify the SPF. Can we generate the same HMACs? '.format(Fore.GREEN))
        change_spf(self.browser.get_spf(), to_change, sid, seed)
        print('{}'.format(Fore.RESET))
        return seed