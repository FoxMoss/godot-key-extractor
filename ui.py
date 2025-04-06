import customtkinter
import concurrent.futures
import os

from utils import extract


class App(customtkinter.CTk):

    def __init__(self):
        super().__init__()

        customtkinter.set_appearance_mode("dark")

        self.geometry("500x200")
        self.title("godot-key-extractor")
        self.grid_columnconfigure(0, weight=1)

        self.title = customtkinter.CTkLabel(
            self, text="godot-key-extractor",
            fg_color="transparent", font=("Times New Roman", 30))
        self.title.grid(row=0, column=0, padx=20, pady=10, columnspan=4)

        self.button = customtkinter.CTkButton(
            self, command=self.select_file, text="Browse")
        self.button.grid(row=4, column=0, padx=20, pady=10)

        self.path = customtkinter.StringVar()
        self.file_path = customtkinter.CTkEntry(
            self, width=220, textvariable=self.path)
        self.file_path.grid(row=4, column=1, padx=0,
                            pady=10, columnspan=2)
        self.path.set(self.get_home())

        self.button = customtkinter.CTkButton(
            self, command=self.button_click, text="Scan for keys..")
        self.button.grid(row=4, column=3, padx=20, pady=10)

        self.progressbar = customtkinter.CTkProgressBar(
            self, orientation="horizontal", width=500-40)
        self.progressbar.grid(row=5, columnspan=4)
        self.progressbar.set(0)

        self.key = customtkinter.StringVar()
        self.key_label = customtkinter.CTkLabel(
            self, fg_color="transparent", textvariable=self.key)
        self.key_label.grid(row=6, column=0, padx=20, pady=10,
                            columnspan=4)

        self.threads = concurrent.futures.ThreadPoolExecutor()

    def key_callback(self):
        self.key.set(extract(self.path.get(), self))

    def button_click(self):
        self.threads.submit(App.key_callback, self)

    def select_file(self):
        filetypes = (
            ('Binaries', '*.x86_64 *.exe'),
            ('All files', '*.*')
        )
        self.path.set(customtkinter.filedialog.askopenfilename(
            title='Select executable',
            initialdir=self.get_home(),
            filetypes=filetypes))

    def get_home(self):
        if os.name == "posix":
            return os.path.expanduser(os.getenv('HOME'))
        return os.path.expanduser(os.getenv('USERPROFILE'))
