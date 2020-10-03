# SecurePreferencesFile

This script does not change any browser settings. It checks whether the browser is exploitable by extracting the seed stored in the resources.pak and computing the HMAC.

Browsers to analyze: Brave, Chrome, Chromium, Microsoft Edge and Opera.

For the HMACs, we obtain a random value and the HMAC from the SPF. If the seed extraction succeded, Before and After values of the HMACs will be equal, otherwise the "after" value will be different. We also computed the super_mac to check the integrity of the whole SPF.
    
# Paper:
    Pablo Picazo-Sanchez, Gerardo Schneider and Andrei Sabelfeld: "HMAC and 'Secure Preferences':
    Revisiting Chromium-based Browsers Security". Conference on Cryptology and Network Security (CANS) 2020.
    Lecture Notes in Computer Science. Springer, Cham, 2020
