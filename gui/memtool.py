from importlib.machinery import ModuleSpec
import importlib.util
from dataclasses import dataclass

import gi
import os
import sys
sys.path.append('../')

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Adw, Gio, Gtk, Gdk, Adw, GLib
from pathlib import Path
from memmod import Process

Adw.init()

BASE_DIR = Path(__file__).resolve().parent

@Gtk.Template(filename=str(BASE_DIR.joinpath('process.ui')))
class ProcessSelectWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'ProcessSelectWindow'
    liststore = Gtk.Template.Child()
    view = Gtk.Template.Child()
    entry_search = Gtk.Template.Child()

    def __init__(self, main_window, **kwargs):
        super().__init__(**kwargs)

        self.main_window = main_window

        self.view.set_search_entry(self.entry_search)
        self.view.set_enable_search(True)
        self.processes = Process.get_all_processes()

        for p in self.processes:
            path = p.get_path_to_executable()
            if path == None:
                continue
            self.liststore.append([p.pid, p.name, path])
        #self.button_process_select_open.set_sensitive(True)

    @Gtk.Template.Callback()
    def action_hide(self, _):
        self.hide()

    @Gtk.Template.Callback()
    def action_open(self, _, i, __):
        pid = self.liststore[i][0]
        self.hide()
        self.main_window.open_process(pid)

    @Gtk.Template.Callback()
    def action_open_button(self, _):
        i = self.view.get_cursor().path
        pid = self.liststore[i][0]
        self.hide()
        self.main_window.open_process(pid)

    @Gtk.Template.Callback()
    def action_open_entry(self, _):
        pid = self.liststore[0][0]
        self.hide()
        self.main_window.open_process(pid)

    @Gtk.Template.Callback()
    def action_open_entry_change(self, entry):
        q = entry.get_text()
        self.liststore.clear()
        for p in self.processes:
            if q in str(p.pid) or q in p.name:
                path = p.get_path_to_executable()
                if path == None:
                    continue
                self.liststore.append([p.pid, p.name, path])

class ExtensionManager():
    def __init__(self) -> None:
        self._widget = None
        self.scripts = []
        self.load_folder("./extensions")

    def load_folder(self, path):
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".py"):
                    self.load_script(os.path.abspath(os.path.join(root,file)))

    def load_script(self, path):
        spec = importlib.util.spec_from_file_location("", path)
        assert type(spec) is ModuleSpec, "Error"
        script = importlib.util.module_from_spec(spec)
        assert spec.loader != None, "Error"
        spec.loader.exec_module(script)

        assert script.info != None, "Script is missing required field `info`"
        assert script.name != None, "Script is missing required field `name`"
        assert script.get_widget != None, "Script is missing required function `get_widget`"

        if hasattr(script, "init"):
            script.init()


        self.scripts.append(script)
        print("Loaded extension:", path)


@Gtk.Template(filename=str(BASE_DIR.joinpath('memtool.ui')))
class MainWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'MainWindow'
    view = Gtk.Template.Child()
    header_bar = Gtk.Template.Child()
    button_more = Gtk.Template.Child()
    button_hambuger = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.process = None

        cssProvider = Gtk.CssProvider()
        cssProvider.load_from_path('style.css')
        self.header_bar.get_style_context().add_provider(cssProvider, 4294967295)

        self.extension_manager = ExtensionManager()

        menu = Gio.Menu.new()
        for script in self.extension_manager.scripts:
            menu.append(script.name, "win.open_tab_script_" + script.name)
            action = Gio.SimpleAction.new("open_tab_script_" + script.name)

            def open_tab_script(action, _):
                widget = script.get_widget(self.process) or Gtk.Label(label='Empty')
                tab = self.create_tab(widget, script.name, script.info)
                self.view.set_selected_page(tab)

            action.connect("activate", open_tab_script)
            self.add_action(action)

        popover = Gtk.PopoverMenu()
        popover.set_menu_model(menu)
        self.button_more.set_popover(popover)

        # Create an action to run a *show about dialog* function we will create 
        action = Gio.SimpleAction.new("about", None)
        action.connect("activate", self.show_about)
        self.add_action(action)

        # Create an action to run the tab menus
        action = Gio.SimpleAction.new("close", None)
        action.connect("activate", self.tab_close)
        self.add_action(action)

    def create_tab(self, widget, title, tooltip):
        tab = self.view.add_page(widget)
        tab.set_title(title)
        tab.set_tooltip(tooltip)
        return tab

    def tab_close(self, action, a):
        page = self.view.get_selected_page()
        self.view.close_page(page)

    def show_about(self, action, param):
        about = Gtk.AboutDialog()
        about.set_transient_for(self)  # Makes the dialog always appear in from of the parent window
        about.set_modal(self)  # Makes the parent window unresponsive while dialog is showing

        about.set_authors(["Daniel Schloegl"])
        about.set_copyright("Copyright 2022 Daniel Schloegl")
        about.set_license_type(Gtk.License.GPL_3_0)
        about.set_version("1.0")
        about.set_logo_icon_name("org.example.example")  # The icon will need to be added to appropriate location
                                                 # E.g. /usr/share/icons/hicolor/scalable/apps/org.example.example.svg
        about.show()

    @Gtk.Template.Callback()
    def show_dialog_process_select(self, _):
        self.dialog_process_select = ProcessSelectWindow(self)
        self.dialog_process_select.set_transient_for(self)
        self.dialog_process_select.show()

    def open_process(self, pid):
        try:
            self.process = Process(pid=pid)
            self.header_bar.get_style_context().add_class("attached")
            path = self.process.get_path_to_executable() or self.process.name
            self.set_title('Attached to ' + path)
            self.button_more.set_sensitive(True)

        except Exception as e:
            self.spawn_error_dialog('Failed to open process:', e)

    def spawn_error_dialog(self, title, message):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=title,
        )
        #dialog.format_secondary_text(message)
        dialog.show()
        dialog.destroy()


class MemmodApplication(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.memmod.memtool", flags=Gio.ApplicationFlags.FLAGS_NONE)

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = MainWindow(application=self)
        win.present()

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def do_shutdown(self):
        Gtk.Application.do_shutdown(self)

if __name__ == '__main__':
    import sys

    app = MemmodApplication()
    app.run(sys.argv)
