# MobileAdapterGB
A collection of scripts and written code to emulate the Mobile GB service.

Code is super WIP, but to use it:

1. Drop the cgb folder and ALL OF ITS CONTENTS onto the root of a web server.
2. Grab this mobilesystem.py script from here: https://github.com/arves100/CGB-B9AJ/blob/master/mobilesystem.py
3. Open mobilesystem.py with a text editor and edit the following:

Line 123:
```
HTTP_HOST_IP = "127.0.0.1"
HTTP_HOST_PORT = 80
POP_HOST_IP = "127.0.0.1"
POP_HOST_PORT = 110
SMTP_HOST_IP = "127.0.0.1"
SMTP_HOST_PORT = 25
EMAIL_DOMAIN = b'xxxxxx.dion.ne.jp'
```

Change HTTP_HOST_IP to point to the web server you're connecting to.

4. Open the Gameboy emulator BGB and open a compatible ROM (For the intents of this repo, Pocket Monsters Crystal (J) is supported currently, as well as the Mobile Trainer for setting up the emulated device), then right-click to get the menu, go to Link, then Listen
5. Open the mobilesystem.py script in a console window and it should connect immediately. BGB will show (linked) in the title if it worked.
6. Do whatever. For the current codebase, obtain the Egg Ticket from the old man in the daycare, then proceed to the Pokemon Communications Center (PCC) in Goldenrod City. Head to the lady to the right of the healing machine, and she should accept your ticket and allow you to connect online. Video here for demonstration: https://www.youtube.com/watch?v=LKhiwaFff28

If you're having issues, it's still a WIP so don't worry too much on this, at least yet ;) Heads up! If you're not able to connect you may have to first set up the Mobile Adapter config file if it doesn't exist or is blank. Games WILL NOT WORK without a configured Mobile Adapter.

See this thread on Glitch City Forums for more information on the Mobile Adapter GB, including uses, tech info, and more!
https://forums.glitchcity.info/index.php?topic=7509.0

Notes:
Future-proof this by adding the following to your Apache httpd.conf:

```BrowserMatch (CGB-) force-response-1.0 downgrade-1.0```

This will force Apache to serve Game Boy Color games with HTTP 1.0 instead of 1.1. This may also work with GBA by replacing CGB with AGB, but this needs further testing to be verified.
