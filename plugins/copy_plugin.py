import loggingimport tkinter as tk__author__ = "Brian Maloney"__version__ = "1.0"log = logging.getLogger(__name__)def copy_action(*args):    """Appends text to the clipboard."""    text = ",".join(args)    try:        root = tk.Tk()        root.withdraw()  # Hide the root window        root.clipboard_clear()        root.clipboard_append(text)        root.update()  # Update the clipboard        root.destroy()    except tk.TclError as e:        log.error(f"Error accessing clipboard: {e}")