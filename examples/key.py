from memmod import Process
from Xlib import XK

from time import sleep

proc = Process(name = "firefox")
win = proc.get_x11_window()[0]

while True:
    proc.send_key(win, XK.string_to_keysym("A"))
    sleep(1)
