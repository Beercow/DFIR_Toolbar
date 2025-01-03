import importlib
import os
import threading
import time
import logging
import sys
from ctypes import Structure, byref, c_uint, sizeof, windll
from ctypes.wintypes import HWND, RECT, UINT
import tkinter as tk
from tkinter import Menu, font

from PIL import Image, ImageDraw
import pygetwindow as gw
from pystray import Icon, MenuItem, Menu as TrayMenu  # Alias pystray.Menu
from screeninfo import get_monitors

import menu_config  # Menu configuration file

__author__ = "Brian Maloney"
__version__ = "2025.01.02"
__email__ = "bmmaloney97@gmail.com"

# Define constants for AppBar
ABM_NEW = 0x00000000
ABM_REMOVE = 0x00000001
ABM_SETPOS = 0x00000003
ABE_TOP = 1

if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))
print(application_path + '/app.log')
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s, %(levelname)s, %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        logging.FileHandler(application_path + '/app.log',
                                            mode='w'
                                            )
                        ]
                    )


# Define APPBARDATA structure
class APPBARDATA(Structure):
    _fields_ = [
        ("cbSize", UINT),
        ("hWnd", HWND),
        ("uCallbackMessage", UINT),
        ("uEdge", UINT),
        ("rc", RECT),
        ("lParam", c_uint),
    ]


# --- Helper Functions ---
# Get primary monitor size
def monitor_size():
    monitors = get_monitors()
    for monitor in monitors:
        if monitor.is_primary:
            return monitor
    raise ValueError("No primary monitor found")


def register_appbar(hwnd, height=40):
    """Registers the toolbar as an AppBar and reserves screen space."""
    abd = APPBARDATA()
    abd.cbSize = sizeof(APPBARDATA)
    abd.hWnd = hwnd
    abd.uEdge = ABE_TOP
    abd.rc = RECT(0, 0, display.width, height)
    windll.shell32.SHAppBarMessage(ABM_NEW, byref(abd))
    windll.shell32.SHAppBarMessage(ABM_SETPOS, byref(abd))
    return abd


def unregister_appbar(abd):
    """Unregisters the AppBar and frees reserved space."""
    windll.shell32.SHAppBarMessage(ABM_REMOVE, byref(abd))


# Function to create a simple icon image
def create_tray_icon_image(width, height, color1, color2):
    image = Image.new('RGB', (width, height), color1)
    dc = ImageDraw.Draw(image)
    dc.rectangle((width // 4, height // 4, width * 3 // 4, height * 3 // 4), fill=color2)
    return image


# Function to toggle toolbar visibility
def toggle_toolbar(app):
    if app.state() == 'withdrawn':
        app.deiconify()
        hwnd = windll.user32.GetForegroundWindow()
        app.abd = register_appbar(hwnd, height=40)

    else:
        unregister_appbar(app.abd)
        app.withdraw()


# Function to quit both the tray icon and the app
def quit_app(icon, app, monitor, monitor_thread):
    monitor.stop()
    monitor_thread.join()
    app.on_close()  # Call the original cleanup method
    icon.stop()


# Function to open the app.log file
def open_log_file():
    log_file = application_path + "/app.log"
    print(log_file)
    if os.path.exists(log_file):
        os.startfile(log_file)


# Create and run the system tray icon
def run_tray_icon(app, monitor, monitor_thread):
    def on_toggle_toolbar():
        toggle_toolbar(app)

    show_toolbar_item = MenuItem(
        'Show Toolbar',
        on_toggle_toolbar,
        checked=lambda item: app.state() != 'withdrawn'
    )

    menu = TrayMenu(
        show_toolbar_item,
        TrayMenu.SEPARATOR,
        MenuItem("Open Log", lambda icon, item: open_log_file()),
        TrayMenu.SEPARATOR,
        MenuItem('Quit', lambda icon, item: quit_app(icon, app, monitor, monitor_thread))
    )
    icon = Icon(
        "DFIR Toolbar",
        create_tray_icon_image(64, 64, 'white', 'blue'),
        menu=menu
    )
    icon.run()


# --- Independent Classes ---
# WindowStateMonitor class
class WindowStateMonitor:
    def __init__(self, polling_interval=1):
        self.polling_interval = polling_interval
        self.prev_state = {}
        self.running = True  # Flag to control the thread

    def monitor_window_state(self):
        while self.running:
            try:
                windows = gw.getWindowsWithTitle("")  # Get all open windows
            except Exception:
                continue

            for window in windows:
                if window.isMaximized:
                    current_state = "maximized"
                elif window.isMinimized:
                    current_state = "minimized"
                else:
                    current_state = "normal"

                if window.title not in self.prev_state or self.prev_state[window.title] != current_state:
                    self.prev_state[window.title] = current_state

                    if current_state == "normal":
                        if window.top <= 39 and window.title != 'DFIR Toolbar' and window.right >= 0:
                            new_position = (window.left, 40)
                            window.moveTo(*new_position)

            time.sleep(self.polling_interval)

    def stop(self):
        """Stops the monitoring loop."""
        self.running = False


# --- Primary Class ---
class ToolbarWithMenus(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DFIR Toolbar")
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.geometry(f"{display.width}x40+0+0")

        self.custom_font = font.Font(family="TkDefaultFont", size=10)
        self.option_add("*Menu.font", self.custom_font)

        self.image_cache = {}
        self.plugins = {}
        self.load_plugins()  # Load plugins dynamically

        hwnd = windll.user32.GetForegroundWindow()
        self.abd = register_appbar(hwnd, height=40)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Load background image
        try:
            self.background_image = tk.PhotoImage(file="icons/toolbar.png")
        except Exception as e:
            logging.error(f"Error loading background image: {e}")
            self.background_image = None

        # Use Canvas to display the background image
        self.toolbar_canvas = tk.Canvas(self, width=display.width, height=40,
                                        bg="gray", bd=0, highlightthickness=0,
                                        relief="flat")
        self.toolbar_canvas.pack(fill=tk.BOTH, expand=True)

        if self.background_image:
            self.toolbar_canvas.create_image(0, 0, anchor=tk.NW,
                                             image=self.background_image)

        for menu_label, menu_conf in menu_config.MENU_CONFIG.items():
            self.create_menu_button(self.toolbar_canvas, menu_label, menu_conf)

        self.update_position(hwnd)

    def load_plugins(self):
        """Dynamically loads plugins from the plugins directory."""
        plugins_dir = "plugins"
        if not os.path.exists(plugins_dir):
            os.makedirs(plugins_dir)

        for filename in os.listdir(plugins_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                module_name = f"{plugins_dir}.{filename[:-3]}"
                module = importlib.import_module(module_name)
                self.plugins[module_name] = module
                logging.info(f"Loaded plugin: {module_name}, Author: {module.__author__}, Version: {module.__version__}")

    def create_menu_button(self, parent, label, menu_items):
        """Creates a button with a popup menu."""
        tearoff = self.is_tearoff(menu_items.get("tearoff"))
        entries = menu_items.get("entries", [])
        menu = Menu(self, tearoff=tearoff, title=label)
        self.add_menu_items(menu, entries)
        btn = tk.Button(parent, text=label, font=self.custom_font,
                        command=lambda: self.show_menu(btn, menu))
        btn.pack(side=tk.LEFT, padx=(4, 0), pady=2)

    def add_menu_items(self, menu, items):
        for item in items:
            if "type" in item and item["type"] == "separator":
                menu.add_separator()
            elif "submenu" in item:
                tearoff = self.is_tearoff(item.get("tearoff"))
                submenu = Menu(menu, tearoff=tearoff)
                self.add_menu_items(submenu, item["submenu"])
                image = self.get_image(item.get("image_path"))
                menu.add_cascade(label=item["label"], menu=submenu,
                                 image=image, compound="left")
            else:
                command = self.get_plugin_command(item["command"]) or \
                          getattr(self, item["command"],
                                  lambda: logging.warning(f"Action '{item['command']} '"
                                                "not implemented"))
                image = self.get_image(item.get("image_path"))
                menu.add_command(label=item["label"], command=command,
                                 image=image, compound="left")

    def get_image(self, image_path):
        """Loads and caches PhotoImage objects."""
        if not image_path:
            return None
        if image_path not in self.image_cache:
            try:
                self.image_cache[image_path] = tk.PhotoImage(file=image_path)
            except Exception as e:
                logging.error(f"Failed to load image '{image_path}': {e}")
                self.image_cache[image_path] = None
        return self.image_cache[image_path]

    def is_tearoff(self, tearoff):
        if tearoff is True:
            return 1
        return 0

    def show_menu(self, widget, menu):
        """Displays the popup menu below the button."""
        x = widget.winfo_rootx()
        y = widget.winfo_rooty() + widget.winfo_height()
        menu.tk_popup(x, y)

    def update_position(self, hwnd):
        """Prevents apps from covering the toolbar."""
        def adjust_position():
            windll.user32.SetWindowPos(
                hwnd, -1, 0, 0, display.width, 40, 0x0001 | 0x0002
            )
            self.after(100, adjust_position)

        adjust_position()

    def on_close(self):
        self.image_cache.clear()  # Clear cached images
        unregister_appbar(self.abd)
        self.destroy()

    def get_plugin_command(self, command_name):
        """Retrieves a command from loaded plugins, supporting parameterized commands."""
        for plugin in self.plugins.values():
            if "(" in command_name and ")" in command_name:
                # Extract the function name and arguments
                func_name, args = command_name.split("(", 1)
                args = args.rstrip(")").split(",")
                args = [arg.strip().strip("'\"") for arg in args]  # Remove quotes and whitespace
                if hasattr(plugin, func_name):
                    return lambda: getattr(plugin, func_name)(*args)
            elif hasattr(plugin, command_name):
                return getattr(plugin, command_name)
        return None


# --- Entry Point ---
if __name__ == "__main__":
    display = monitor_size()
    app = ToolbarWithMenus()

    # Start the WindowStateMonitor in a separate thread
    monitor = WindowStateMonitor(polling_interval=1)
    monitor_thread = threading.Thread(target=monitor.monitor_window_state,
                                      daemon=True)
    monitor_thread.start()

    # Ensure the monitor stops when the app is closed
    def on_close_with_monitor():
        monitor.stop()  # Stop the monitor
        monitor_thread.join()  # Wait for the thread to finish
        app.on_close()  # Call the original cleanup method

    # Run the tray icon in a separate thread to avoid blocking
    tray_thread = threading.Thread(target=run_tray_icon, args=(app, monitor, monitor_thread), daemon=True)
    tray_thread.start()

    app.protocol("WM_DELETE_WINDOW", on_close_with_monitor)
    app.mainloop()
