#!/usr/bin/env python

import time
from pyswitcherv2 import switcher

phone_id = "xxxx"
dev_id = "xxxxxx"
dev_pass = "xxxxxxxx"
switcher_local_ip = "192.168.x.x"

credentials = switcher.Credentials(phone_id, dev_id, dev_pass, switcher_local_ip)
credentials.validate()
is_debug = True
switcher = switcher.Switcher(credentials, is_debug)
time_minutes = 30
switcher.turn_on(time_minutes)
time.sleep(5)
switcher.get_state()
time.sleep(5)
switcher.turn_off()

