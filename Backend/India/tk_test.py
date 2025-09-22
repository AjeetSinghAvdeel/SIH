import tkinter as tk

root = tk.Tk()
root.title("Tkinter Test")
root.geometry("300x100")
tk.Label(root, text="If you see this, Tkinter works!").pack(pady=20)
root.mainloop()
