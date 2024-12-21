import tkinter as tk

import CeasarCipher
import DES
import AES
import RSA
import SHA
import MD5
import binascii
from tkinter import messagebox
import random
class App(tk.Tk):
    def __init__(self, master=None):
        self.master = master
        self.frame = tk.Frame(self.master)
        self.master.title("Cryptography")
        #self.geometry("500x250")
        #self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.menu_bar = tk.Menu(master)
        master.config(menu=self.menu_bar)

        # Create the file menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.on_closing)

        # Create the algorithms menu
        algo_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Algorithms", menu=algo_menu)
        algo_menu.add_command(label="Caesar Cipher", command=self.open_caesar_ui)
        algo_menu.add_command(label="DES", command=self.open_des_ui)
        algo_menu.add_command(label="AES", command=self.open_aes_ui)
        algo_menu.add_command(label="RSA", command=self.open_rsa_ui)

        # Create hash functions menu
        hash_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Hash Functions", menu=hash_menu)
        hash_menu.add_command(label='SHA', command=self.open_sha_ui)
        hash_menu.add_command(label='MD5',  command=self.open_md5_ui)

        self.frame.pack()

    def open_caesar_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = CaesarUI(self.new_window)

    def open_des_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = DESUI(self.new_window)

    def open_aes_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = AESUI(self.new_window)

    def open_rsa_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = RSAUI(self.new_window)
        
    def open_sha_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = SHAUI(self.new_window)
    
    def open_md5_ui(self):
        self.new_window = tk.Toplevel(self.master)
        self.app = MD5UI(self.new_window)
        
    def on_closing(self):

        if messagebox.askokcancel("Quit", "Are you sure?"):
            self.master.destroy()


class CaesarUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Ceasar Algorithm")
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)

        self.shift_label = tk.Label(self, text="SHIFT")
        self.shift_label.grid(row=2, column=0, padx=10, pady=10)
        self.shift_value = tk.Entry(self)
        self.shift_value.grid(row=3, column=0, padx=10, pady=10)

        self.encrypt_button = tk.Button(self, text="ENCRYPT", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(self, text="DECRYPT", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10)

        self.random_shift_button = tk.Button(self, text="RANDOM SHIFT", command=self.random_shift)
        self.random_shift_button.grid(row=4, column=2, padx=10, pady=10)

    def encrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        shift = int(self.shift_value.get())
        encrypted_text = ''.join(CeasarCipher.encrypt(text, shift))
                                 
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)

    def decrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        shift = int(self.shift_value.get())
        decrypted_text = ''.join(CeasarCipher.decrypt(text, shift))
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted_text)
    def random_shift(self):
        shift = random.randint(1, 25)
        self.shift_value.delete(0, tk.END)
        self.shift_value.insert(tk.END, str(shift))

class DESUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self,master.title("DES Algorithm")
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        # Add DES specific UI components here
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)

        self.key_label = tk.Label(self, text="KEY")
        self.key_label.grid(row=2, column=0, padx=10, pady=10)
        self.key_value = tk.Entry(self)
        self.key_value.grid(row=3, column=0, padx=10, pady=10)

        self.encrypt_button = tk.Button(self, text="ENCRYPT", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(self, text="DECRYPT", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10)

        self.random_shift_button = tk.Button(self, text="RANDOM KEY", command=self.random_key)
        self.random_shift_button.grid(row=4, column=2, padx=10, pady=10)
        
    def encrypt(self):
        key = binascii.unhexlify(self.key_value.get())
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes long")
            return
        text = self.input_text.get("1.0", tk.END).strip()
        encrypted_text = DES.encrypt(text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)

    def decrypt(self):
        key = binascii.unhexlify(self.key_value.get())
        if len(key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes long")
            return
        encrypted_text = self.input_text.get("1.0", tk.END).strip()
        decrypted_text = DES.decrypt(encrypted_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted_text)

    def random_key(self):
        key = DES.random_key()
        self.key_value.delete(0, tk.END)
        self.key_value.insert(tk.END, binascii.hexlify(key).decode('utf-8'))
        
        

class AESUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("AES Algorithm")
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        # Add AES specific UI components here
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)

        self.key_label = tk.Label(self, text="KEY")
        self.key_label.grid(row=2, column=0, padx=10, pady=10)
        self.key_value = tk.Entry(self)
        self.key_value.grid(row=3, column=0, padx=10, pady=10)

        self.encrypt_button = tk.Button(self, text="ENCRYPT", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(self, text="DECRYPT", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10)

        self.random_shift_button = tk.Button(self, text="RANDOM KEY", command=self.random_key)
        self.random_shift_button.grid(row=4, column=2, padx=10, pady=10)
        
        self.key_len_label = tk.Label(self, text="LENGTH KEY")
        self.key_listbox = tk.Listbox(self.algo_frame, width=10, height=1, selectmode="single")
        self.key_len_label.grid(row=2, column=1, padx=10, pady=10)
        self.key_listbox.grid(row=3, column=1, padx=10, pady=10)
        
        items = [16, 24, 32]
        for item in items:
            self.key_listbox.insert(tk.END, str(item))
            
    def encrypt(self):
        key = binascii.unhexlify(self.key_value.get())
        text = self.input_text.get("1.0", tk.END).strip()
        encrypted_text = AES.encrypt(text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)

    def decrypt(self):
        key = binascii.unhexlify(self.key_value.get())
        encrypted_text = self.input_text.get("1.0", tk.END).strip()
        decrypted_text = AES.decrypt(encrypted_text, key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, decrypted_text)

    def random_key(self):
        selected_index = self.key_listbox.curselection()
        key_lenght = int(self.key_listbox.get(selected_index))
        key = AES.generate_aes_key(key_lenght)
        self.key_value.delete(0, tk.END)
        self.key_value.insert(tk.END, binascii.hexlify(key).decode('utf-8'))
        
        
class RSAUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("RSA Algorithm")
        self.pack()
        self.create_widgets()

    def create_widgets(self):
        # Add RSA specific UI components here
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)

        self.puk_label = tk.Label(self, text="PUBLIC KEY")
        self.puk_label.grid(row=2, column=0, padx=10, pady=10)
        self.puk_value = tk.Entry(self)
        self.puk_value.grid(row=3, column=0, padx=10, pady=10)
        
        self.prk_label = tk.Label(self, text='PRIVATE KEY')
        self.prk_label.grid(row=2, column=1, padx=10, pady=10)
        self.prk_value = tk.Entry(self)
        self.prk_value.grid(row=3, column=1, padx=10, pady=10)
        
        self.key_len_label = tk.Label(self, text="KEY LENGTH")
        self.key_len_label.grid(row=2, column=2, padx=10, pady=10)
        self.key_len_value = tk.Entry(self)
        self.key_len_value.grid(row=3, column=2, padx=10, pady=10)

        self.encrypt_button = tk.Button(self, text="ENCRYPT", command=self.encrypt)
        self.encrypt_button.grid(row=4, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(self, text="DECRYPT", command=self.decrypt)
        self.decrypt_button.grid(row=4, column=1, padx=10, pady=10)

        self.random_shift_button = tk.Button(self, text="RANDOM KEY", command=self.random_key)
        self.random_shift_button.grid(row=4, column=2, padx=10, pady=10)
        
    def encrypt(self):
        # Encrypt the input text using the public key
        #public_key = self.puk_value.get()
        text = self.input_text.get("1.0", tk.END).strip()
        encrypted_text = RSA.encrypt(text, public_key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)
    
    def decrypt(self):
        #private_key = self.puk_value.get()
        text = self.input_text.get("1.0", tk.END).strip()
        encrypted_text = RSA.decrypt(text, private_key)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, encrypted_text)
    
    def random_key(self):
        global public_key, private_key 
        public_key, private_key = RSA.generate_key(int(self.key_len_value.get()))
        self.puk_value.delete(0, tk.END)
        self.puk_value.insert(tk.END, str(public_key))
        self.prk_value.delete(0, tk.END)
        self.prk_value.insert(tk.END, str(private_key))
        
class SHAUI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widget()
        
    
    def create_widget(self):
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)

        self.algo_label = tk.Label(self, text="SHA Algorithms")
        self.algo_label.grid(row=2, column=1, padx=10, pady=10)

        # Create a Frame to hold the listbox and scrollbar
        self.algo_frame = tk.Frame(self)
        self.algo_frame.grid(row=3, column=1, padx=10, pady=10)

        self.algo_listbox = tk.Listbox(self.algo_frame, width=10, height=1, selectmode="single")
        self.algo_listbox.pack(side="left", fill="both", expand=1)
        
        

        items = ['sha256', 'sha512', 'sha224', 'sha1', 'sha3_256']
        for item in items:
            self.algo_listbox.insert(tk.END, str(item))
            
        self.scroll_bar = tk.Scrollbar(self.algo_frame, orient="vertical", command=self.algo_listbox.yview)
        self.scroll_bar.pack(side="right", fill="y")

        #self.scroll_bar.config(command=lambda *args: on_scroll(*args))

        self.hash_button = tk.Button(self, text='Hash', command=self.hash_function)
        self.hash_button.grid(row=3, column=0, padx=10, pady=10)
        
    
        
    def hash_function(self):
        text = self.input_text.get("1.0", tk.END).strip()
        selected_index = self.algo_listbox.curselection()
        hash_algo = self.algo_listbox.get(selected_index)
        hashed_text = SHA.hash_function(text, hash_algo)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, hashed_text)
        
    
class MD5UI(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_widget()
        
    def create_widget(self):
        self.input_label = tk.Label(self, text="INPUT")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_text = tk.Text(self, height=10, width=30)
        self.input_text.grid(row=1, column=0, padx=10, pady=10)

        self.output_label = tk.Label(self, text="OUTPUT")
        self.output_label.grid(row=0, column=1, padx=10, pady=10)
        self.output_text = tk.Text(self, height=10, width=30)
        self.output_text.grid(row=1, column=1, padx=10, pady=10)
        
        self.hash_button = tk.Button(self, text='Hash', command=self.md5hash)
        self.hash_button.grid(row=3, column=0, padx=10, pady=10)
        
    def md5hash(self):
        text = self.input_text.get("1.0", tk.END).strip()
        hashed_text = MD5.md5_hash(text)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, hashed_text)
        
        

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
