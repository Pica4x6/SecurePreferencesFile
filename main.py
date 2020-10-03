import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))
from sys import platform
from colorama import Fore
from macos import MacOS
from windows import WindowsOS

if __name__ == "__main__":
    
    print('''This script does not change any browser settings. It checks whether the browser is exploitable by
extracting the seed stored in the resources.pak and computing the HMAC.
          
Browsers to analyze: Brave, Chrome, Chromium, Microsoft Edge and Opera.
          
For the HMACs, we obtain a random value and the HMAC from the SPF. If the seed extraction succeded, Before and After
values of the HMACs will be equal, otherwise the "after" value will be different. We also computed the super_mac to
check the integrity of the whole SPF.
    
    Paper:
        Pablo Picazo-Sanchez, Gerardo Schneider and Andrei Sabelfeld: "HMAC and 'Secure Preferences':
        Revisiting Chromium-based Browsers Security". Conference on Cryptology and Network Security (CANS) 2020.
        Lecture Notes in Computer Science. Springer, Cham, 2020
    
    ''')
    
    
    browsers = ['Brave', 'Chrome', 'Chromium', 'Edge', 'Opera']

    if platform == "linux" or platform == "linux2":
        print('{}This Proof-of-Concept works in Mac and Windows. In case you want to run it on Linux, '
              'read our paper and happy coding!!{}'.format(Fore.RED, Fore.RESET))
    else:
        for browser in browsers:
            print('Browser: {}'.format(browser))
            
            if platform == "darwin":
                attack = MacOS(browser)
            elif platform == "win32":
                attack = WindowsOS(browser)
        
            resources = attack.get_resources()
            
            data = {
                'OS': platform,
                'Browser':browser
            }
            if attack.browser_version:
                data['version'] = attack.browser_version
            
            try:
                seed = attack.look_for_seed(resources)
                if attack.expected_seed == seed:
                    data['seed'] = attack.expected_seed
                else:
                    print('{} NEW Seed! {}'.format(Fore.BLUE, Fore.RESET))
                    data['seed'] = seed
                print ('{}data: {}{}'.format(Fore.BLUE, data, Fore.RESET))
            except Exception as e:
                print(e)
                print('{}{}: '.format(Fore.RED,browser), end="")
                print('Either the browser does not exist or the paths are not correct{}'.format(Fore.RESET))

            print()