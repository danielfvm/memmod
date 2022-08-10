from gi.repository import Adw, Gio, Gtk, Gdk
from pathlib import Path

from memmod import Process

info = "A small test script to check if this is working"
name = "Test"


BASE_DIR = Path(__file__).resolve().parent
@Gtk.Template(filename=str(BASE_DIR.joinpath('test.ui')))
class Test(Gtk.Box):
    __gtype_name__ = 'Test'

    liststore = Gtk.Template.Child()

    def __init__(self, proc: Process, **kwargs):
        super().__init__(**kwargs)

        for m in proc.modules:
            self.liststore.append(["%x" % m.start, "%x" % m.end, m.mode, "%x" % m.offset, "%d:%d" % (m.major, m.minor), m.inode, m.path])

def init():
    print("hello")

def get_widget(proc: Process):
    return Test(proc)
