import sys
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_default_size(800, 550)
        self.set_title("Memory Tool")

        # Create a new menu, containing that action
        menu = Gio.Menu.new()
        menu.append("Do Something", "win.something")  # Or you would do app.something if you had attached the
                                                      # action to the application
        menu.append("About", "win.about")  # Add it to the menu we created in previous section

        # Create an action to run a *show about dialog* function we will create 
        action = Gio.SimpleAction.new("about", None)
        action.connect("activate", self.show_about)
        self.add_action(action)


        self.header = Gtk.HeaderBar()
        self.set_titlebar(self.header)

        self.open_button = Gtk.Button(label="Open")
        self.open_button.set_icon_name("document-open-symbolic")
        self.open_button.connect("clicked", self.select_file)
        self.header.pack_start(self.open_button)

        self.addtab_button = Gtk.Button(label="New tab")
        self.addtab_button.set_icon_name("document-new")
        self.addtab_button.connect("clicked", self.add_new_tab)
        self.header.pack_start(self.addtab_button)

        # Create a popover
        self.popover = Gtk.PopoverMenu()  # Create a new popover menu
        self.popover.set_menu_model(menu)

        # Create a menu button
        self.hamburger = Gtk.MenuButton()
        self.hamburger.set_popover(self.popover)
        self.hamburger.set_icon_name("open-menu-symbolic")  # Give it a nice icon

        # Add menu button to the header bar
        self.header.pack_end(self.hamburger)

        self.notebook = Gtk.Notebook()
        self.notebook.set_show_border(False)
        self.set_child(self.notebook)
        self.add_new_tab(None)

        self.open_dialog = Gtk.FileChooserNative.new(title="Choose a file", parent=self, action=Gtk.FileChooserAction.OPEN)
        self.open_dialog.connect("response", self.open_response)
        f = Gtk.FileFilter()
        f.set_name("Executable files")
        f.add_mime_type("application/x-executable")
        self.open_dialog.add_filter(f)

    def select_file(self, _):
        self.open_dialog.show()

    def open_response(self, dialog, response):
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            filename = file.get_path()
            print(filename)  # Here you could handle opening or saving the file

    def select_process(self, _):
        print("test")


    def add_new_tab(self, _):
        page = Gtk.Label(label='This is the first page')
        self.notebook.append_page(page, Gtk.Label(label='Empty'))
        self.notebook.set_tab_reorderable(page, True)
        self.notebook.set_tab_detachable(page, False)
        self.notebook.set_current_page(self.notebook.get_n_pages()-1)

    def show_about(self, action, param):
        self.about = Gtk.AboutDialog()
        self.about.set_transient_for(self)  # Makes the dialog always appear in from of the parent window
        self.about.set_modal(self)  # Makes the parent window unresponsive while dialog is showing

        self.about.set_authors(["Daniel Schloegl"])
        self.about.set_copyright("Copyright 2022 Daniel Schloegl")
        self.about.set_license_type(Gtk.License.GPL_3_0)
        self.about.set_version("1.0")
        self.about.set_logo_icon_name("org.example.example")  # The icon will need to be added to appropriate location
                                                 # E.g. /usr/share/icons/hicolor/scalable/apps/org.example.example.svg

        self.about.show()

class MyApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        self.win = MainWindow(application=app)
        self.win.present()

app = MyApp(application_id="at.deancode.memtool")
app.run(sys.argv)
