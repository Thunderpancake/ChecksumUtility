from tkinter import *
from tkinter.filedialog import askopenfilename
import hashlib


class Application(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master
        self.pack()
        self.master.title("Checksum Utility")
        self.file_name = StringVar()
        self.md5_checksum = StringVar()
        self.sha1_checksum = StringVar()
        self.sha256_checksum = StringVar()
        self.sha512_checksum = StringVar()
        self.create_widgets()

    def create_widgets(self):
        self.file_label = Label(self, text="File")
        self.md5_label = Label(self, text="MD5")
        self.sha1_label = Label(self, text="SHA-1")
        self.sha256_label = Label(self, text="SHA-256")
        self.sha512_label = Label(self, text="SHA-512")

        self.file_text = Entry(self, width=128, textvariable=self.file_name)
        self.md5_text = Entry(self, width=128, textvariable=self.md5_checksum)
        self.sha1_text = Entry(self, width=128, textvariable=self.sha1_checksum)
        self.sha256_text = Entry(self, width=128, textvariable=self.sha256_checksum)
        self.sha512_text = Entry(self, width=128, textvariable=self.sha512_checksum)

        self.load_button = Button(self, text="Browse", command=self.open_file_dialog)

        self.file_label.grid(row=0, column=0, sticky=E)
        self.md5_label.grid(row=1, column=0, sticky=E)
        self.sha1_label.grid(row=2, column=0, sticky=E)
        self.sha256_label.grid(row=3, column=0, sticky=E)
        self.sha512_label.grid(row=4, column=0, sticky=E)

        self.file_text.grid(row=0, column=1, sticky=W+E)
        self.md5_text.grid(row=1, column=1, )
        self.sha1_text.grid(row=2, column=1)
        self.sha256_text.grid(row=3, column=1)
        self.sha512_text.grid(row=4, column=1)

        self.load_button.grid(row=0, column=2)

    def open_file_dialog(self):
        self.file_name.set(askopenfilename())
        print(self.file_name.get())
        self.md5_checksum.set(checksum_md5(self.file_name.get()))
        self.sha1_checksum.set(checksum_sha1(self.file_name.get()))
        self.sha256_checksum.set(checksum_sha256(self.file_name.get()))
        self.sha512_checksum.set(checksum_sha512(self.file_name.get()))


def checksum_md5(file):
    m = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(128 * m.block_size), b''):
            m.update(chunk)
    return m.hexdigest()


def checksum_sha1(file):
    m = hashlib.sha1()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(128 * m.block_size), b''):
            m.update(chunk)
    return m.hexdigest()


def checksum_sha256(file):
    m = hashlib.sha256()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(128 * m.block_size), b''):
            m.update(chunk)
    return m.hexdigest()


def checksum_sha512(file):
    m = hashlib.sha512()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(128 * m.block_size), b''):
            m.update(chunk)
    return m.hexdigest()


if __name__ == "__main__":
    root = Tk()
    app = Application(root)
    app.mainloop()

