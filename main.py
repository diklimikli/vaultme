import ttkbootstrap as tb
from gui import PasswordManagerApp

if __name__ == "__main__":
    root = tb.Window(themename="solar")
    app = PasswordManagerApp(root)
    root.mainloop()
