import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess, os, sys

class RecompilerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNES Recompiler GUI")
        self.geometry("400x300")

        self.listbox = tk.Listbox(self, height=10)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10)

        tk.Button(btn_frame, text="Add ROM…", command=self.add_rom).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Compile", command=self.compile_selected).pack(side=tk.RIGHT)

    def add_rom(self):
        paths = filedialog.askopenfilenames(
            title="Select SNES ROMs",
            filetypes=[("SNES ROM", "*.sfc *.smc")]
        )
        for p in paths:
            self.listbox.insert(tk.END, p)

    def compile_selected(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Please select a ROM.")
            return
        rom = self.listbox.get(sel[0])
        asm = rom + ".asm"
        cmd = ["recompiler.exe", rom, asm]
        try:
            res = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            messagebox.showinfo("Success", f"Output: {asm}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", e.stderr.decode() or "Recompile failed.")

if __name__ == '__main__':
    if not os.path.exists("recompiler.exe"):
        messagebox.showerror("Missing", "recompiler.exe not found.")
        sys.exit(1)
    app = RecompilerGUI()
    app.mainloop()

