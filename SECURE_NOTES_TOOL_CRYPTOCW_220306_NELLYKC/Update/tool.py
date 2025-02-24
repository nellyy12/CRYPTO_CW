import tkinter as tk
from tkinter import messagebox, Listbox
import pymysql
import uuid
import os
import pyperclip

from Module.stream_cipher import ChaCha20
from Module.block_cipher import AES_GCM
from Module.hashing import SHA256
from Module.digital_signature import ECDSA
import os


# 🎨 Final Updated GUI Theme Colors
BG_COLOR = "#E6B3B3"  # Baby Pink
BTN_COLOR = "#D1B3E0"  # Baby Purple
TEXT_COLOR = "white"
INPUT_BG = "#C2A2E0"  # Light Purple


# 🚀 Database Connection
def connect_to_db():
    return pymysql.connect(host='localhost', user='root', password='', database='secure_notes')


# 🔐 Password Hashing (SHA-256)
def hash_password(password):
    return SHA256.hash_password(password)  # Uses salting + key stretching



# 🔑 Key Derivation (PBKDF2 for AES & ChaCha20)
def generate_cipher_key(password):
    hashed = SHA256.hash(password)
    return hashed[:32].encode()  # Ensure 32-byte key for AES & ChaCha20



# 🔐 Stream Cipher (ChaCha20) Encryption & Decryption
def encrypt_note_chacha20(key, plaintext):
    nonce = os.urandom(12)
    chacha = ChaCha20(key, nonce)
    return nonce + chacha.encrypt(plaintext.encode())

def decrypt_note_chacha20(key, ciphertext):
    nonce = ciphertext[:12]
    chacha = ChaCha20(key, nonce)
    return chacha.decrypt(ciphertext[12:]).decode()


# 🔐 Block Cipher (AES-GCM) Encryption & Decryption
def encrypt_note_aes_gcm(key, plaintext):
    aes = AES_GCM(key)
    return aes.encrypt(plaintext)

def decrypt_note_aes_gcm(key, ciphertext):
    aes = AES_GCM(key)
    return aes.decrypt(ciphertext)



def generate_key_pair():
    private_key, public_key_pem = ECDSA.generate_key_pair()
    return private_key, public_key_pem

def sign_data(private_key, data):
    return ECDSA.sign(private_key, data)

def verify_signature(public_key_pem, signature, data):
    return ECDSA.verify(public_key_pem, signature, data)



def main_menu(root, username):
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("500x400")
    root.configure(bg=BG_COLOR)

    tk.Label(root, text=f"Welcome {username}!", font=("Arial", 18, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=20)

    btn_style = {"font": ("Arial", 14, "bold"), "width": 20, "height": 2}

    tk.Button(root, text="📝 Create Note", bg=BTN_COLOR, fg=TEXT_COLOR, **btn_style, 
          command=lambda: create_note_window(root, username)).pack(pady=5)

    tk.Button(root, text="📜 View Notes", bg=BTN_COLOR, fg=TEXT_COLOR, **btn_style, 
              command=lambda: view_notes_window(root, username)).pack(pady=5)

    tk.Button(root, text="🔑 View Note by Token", bg=BTN_COLOR, fg=TEXT_COLOR, **btn_style, 
              command=lambda: view_note_by_token_window(root, username)).pack(pady=5)

    tk.Button(root, text="🚪 Logout", bg="red", fg=TEXT_COLOR, font=("Arial", 14, "bold"), width=20, height=2,
              command=lambda: logout(root)).pack(pady=10)



    root.update_idletasks()

def login_window():
    """Creates the login window for user authentication."""
    root = tk.Tk()
    root.title("Secure Notes Login")
    root.geometry("450x350")
    root.configure(bg=BG_COLOR)

    tk.Label(root, text="🔐 Secure Notes Login", font=("Arial", 18, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=20)

    input_style = {"font": ("Arial", 14), "width": 25}

    # 📝 Username Field
    tk.Label(root, text="Username", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    username_entry = tk.Entry(root, **input_style)
    username_entry.pack(pady=5)

    # 🔑 Password Field
    tk.Label(root, text="Password", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    password_entry = tk.Entry(root, show="*", **input_style)  # Hide password input
    password_entry.pack(pady=5)

    btn_style = {"font": ("Arial", 14, "bold"), "width": 20, "height": 2}

    def attempt_login():
      username = username_entry.get().strip()
      password = password_entry.get().strip()

      if not username or not password:
          messagebox.showerror("❌ Error", "Username and Password cannot be empty!")
          return

      conn = connect_to_db()
      cursor = conn.cursor()
      cursor.execute("SELECT password_hash, public_key FROM users WHERE username=%s", (username,))
      result = cursor.fetchone()
      conn.close()

      if not result:
          messagebox.showerror("❌ Error", "User does not exist!")
          return

      stored_password_hash, public_key_pem = result

      # ✅ Verify Password
      if not SHA256.verify_password(password, stored_password_hash):
          messagebox.showerror("❌ Error", "Invalid password!")
          return


      try:
          # ✅ Load the user's private key
          private_key = ECDSA.load_private_key(f"{username}_private.pem")
          if private_key is None:
              messagebox.showerror("Error", "Private key not found! You must have registered on this device.")
              return
      except FileNotFoundError:
          messagebox.showerror("Error", "Private key not found! You must have registered on this device.")
          return

      # 🔐 Digital Signature Authentication
      challenge = os.urandom(32)  # Random challenge
      signature = sign_data(private_key, challenge.hex())

      if verify_signature(public_key_pem, signature, challenge.hex()):
          messagebox.showinfo("✅ Success", "Login successful!")

          # 🛠 Fix: Instead of withdrawing the root window, destroy it and create a new one
          root.destroy()  # Close login window

          # ✅ Open the main menu in a new Tkinter window
          new_root = tk.Tk()
          main_menu(new_root, username)  # Open the main menu with a new root
      else:
          messagebox.showerror("❌ Error", "Invalid digital signature! Authentication failed.")


    # 🚀 Buttons
    tk.Button(root, text="Login", bg=BTN_COLOR, fg=TEXT_COLOR, **btn_style, command=attempt_login).pack(pady=10)
    tk.Button(root, text="Register", bg=INPUT_BG, fg=TEXT_COLOR, **btn_style, command=lambda: register_window(root)).pack(pady=5)

    root.mainloop()


# 🚀 Register a New User
def register_user(username, password):
    hashed_password = SHA256.hash_password(password)  # Generates salt + hash
    private_key, public_pem = generate_key_pair()

    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, public_key) VALUES (%s, %s, %s)",
                   (username, hashed_password, public_pem))
    conn.commit()
    conn.close()

    ECDSA.save_private_key(private_key, f"{username}_private.pem")


def register_window(parent):
    """Creates the registration window for new users."""
    parent.destroy()  # Close the login window

    reg_win = tk.Tk()
    reg_win.title("Register")
    reg_win.geometry("450x350")
    reg_win.configure(bg=INPUT_BG)  # Dark Pink Background

    tk.Label(reg_win, text="📝 Create Account", font=("Arial", 18, "bold"), fg=TEXT_COLOR, bg=INPUT_BG).pack(pady=20)

    input_style = {"font": ("Arial", 14), "width": 25}

    tk.Label(reg_win, text="Username", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=INPUT_BG).pack()
    username_entry = tk.Entry(reg_win, **input_style)
    username_entry.pack(pady=5)

    tk.Label(reg_win, text="Password", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=INPUT_BG).pack()
    password_entry = tk.Entry(reg_win, show="*", **input_style)
    password_entry.pack(pady=5)

    btn_style = {"font": ("Arial", 14, "bold"), "width": 20, "height": 2}

    def create_account():
        username = username_entry.get().strip()
        password = password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("❌ Error", "Username and Password cannot be empty!")
            return

        hashed_password = hash_password(password)

        # **Generate Digital Signature Key Pair**
        private_key, public_pem = generate_key_pair()

        try:
            conn = connect_to_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, public_key) VALUES (%s, %s, %s)",
                           (username, hashed_password, public_pem))
            conn.commit()
            conn.close()

            # **Save Private Key Locally (User Must Keep It Safe)**
            ECDSA.save_private_key(private_key, f"{username}_private.pem")


            messagebox.showinfo("✅ Success", "Account created successfully!\nYour private key has been saved.")
            reg_win.destroy()
            login_window()  # Redirect back to login

        except pymysql.err.IntegrityError:
            messagebox.showerror("❌ Error", "Username already exists!")

    tk.Button(reg_win, text="Register", bg=BTN_COLOR, fg=TEXT_COLOR, **btn_style, command=create_account).pack(pady=10)
    tk.Button(reg_win, text="Back", bg="gray", fg=TEXT_COLOR, **btn_style, command=lambda: [reg_win.destroy(), login_window()]).pack(pady=5)

    reg_win.mainloop()

# 🔑 User Login with Digital Signature
def login_user(username):
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return False

    public_key_pem = result[0]

    try:
          private_key = ECDSA.load_private_key(f"{username}_private.pem")
          if private_key is None:
              messagebox.showerror("Error", "Private key not found! You must have registered on this device.")
              return
    except FileNotFoundError:
        return False

    challenge = os.urandom(32)
    signature = sign_data(private_key, challenge.hex())

    return verify_signature(public_key_pem, signature, challenge.hex())

def create_note_window(root, username):
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("500x500")
    root.configure(bg=BG_COLOR)

    tk.Label(root, text="Create Note", font=("Arial", 14, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=10)

    tk.Label(root, text="Title", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    title_entry = tk.Entry(root, width=50)
    title_entry.pack(pady=5)

    tk.Label(root, text="Content", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    content_text = tk.Text(root, height=10, width=50)
    content_text.pack(pady=5)

    # **Token Display**
    tk.Label(root, text="Token:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    token_entry = tk.Entry(root, width=50, state="readonly")
    token_entry.pack(pady=5)

    def save_note():
        if token_entry.get():
            return  # Prevent duplicate UI updates

        title = title_entry.get().strip()
        content = content_text.get("1.0", tk.END).strip()
        if not title or not content:
            messagebox.showerror("Error", "Title and content cannot be empty!")
            return

        key = generate_cipher_key(username)
        encrypted_content_chacha = encrypt_note_chacha20(key, content)
        encrypted_content_aes = encrypt_note_aes_gcm(key, content)
        note_token = str(uuid.uuid4())

        private_key = ECDSA.load_private_key(f"{username}_private.pem")
        if private_key is None:
            messagebox.showerror("Error", "Private key not found! You must have registered on this device.")
            return
        signature = sign_data(private_key, content)

        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO notes (user_id, title, chacha_encrypted, aes_encrypted, token, signature) 
            VALUES ((SELECT id FROM users WHERE username=%s), %s, %s, %s, %s, %s)
        """, (username, title, encrypted_content_chacha, encrypted_content_aes, note_token, signature))
        conn.commit()
        conn.close()

        token_entry.config(state="normal")
        token_entry.delete(0, tk.END)
        token_entry.insert(0, note_token)
        token_entry.config(state="readonly")

        messagebox.showinfo("Success", "Note saved successfully!")

    def copy_token():
        if token_entry.get():
            pyperclip.copy(token_entry.get())
            messagebox.showinfo("Copied", "Token copied to clipboard!")

    # **Buttons**
    tk.Button(root, text="Copy Token", font=("Arial", 12), bg=BTN_COLOR, fg=TEXT_COLOR, command=copy_token).pack(pady=5)
    tk.Button(root, text="Save", font=("Arial", 12), bg="green", fg=TEXT_COLOR, command=save_note).pack(pady=5)
    tk.Button(root, text="🔙 Back", bg="gray", fg=TEXT_COLOR, font=("Arial", 12), 
          command=lambda: main_menu(root, username)).pack(pady=5)


    root.update_idletasks()

# 📝 Save Notes with Both Ciphers & Signature
def save_note(username, title, content):
    key = generate_cipher_key(username)
    
    # 🔐 Sign BEFORE Encrypting (Correct Order)
    private_key = ECDSA.load_private_key(f"{username}_private.pem")
    if private_key is None:
        messagebox.showerror("Error", "Private key not found! You must have registered on this device.")
        return
    signature = sign_data(private_key, content)  # ✅ Sign plaintext note
    
    # 🔒 Encrypt Note
    chacha_encrypted = encrypt_note_chacha20(key, content)
    aes_encrypted = encrypt_note_aes_gcm(key, content)

    # 📌 Store in Database
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notes (user_id, title, chacha_encrypted, aes_encrypted, signature) 
        VALUES ((SELECT id FROM users WHERE username=%s), %s, %s, %s, %s)
    """, (username, title, chacha_encrypted, aes_encrypted, signature))
    conn.commit()
    conn.close()



# 🔍 View Notes & Verify Signature
def view_note(username, note_id):
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT chacha_encrypted, aes_encrypted, signature FROM notes WHERE note_id=%s", (note_id,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        return None

    chacha_encrypted, aes_encrypted, signature = result
    key = generate_cipher_key(username)

    # 🔓 Decrypt Content
    decrypted_content_chacha = decrypt_note_chacha20(key, chacha_encrypted)
    decrypted_content_aes = decrypt_note_aes_gcm(key, aes_encrypted)

    print("Original Decrypted Content (AES):", decrypted_content_aes)  # Debugging
    print("Signature from Database:", signature)  # Debugging

    # 🔑 Get Public Key for Verification
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    public_key_pem = cursor.fetchone()[0]
    conn.close()

    # ✅ Verify Signature with Decrypted Content
    try:
        is_valid = verify_signature(public_key_pem, signature, decrypted_content_aes)
        print("Signature Verification Result:", is_valid)  # Debugging
    except Exception as e:
        print("Signature Verification Error:", e)

    if not is_valid:
        messagebox.showerror("Error", "Signature verification failed! The note might be tampered with.")
        return None

    return decrypted_content_aes



def view_note_by_token_window(root, username):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="View Note by Token", font=("Arial", 14, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=10)
    
    tk.Label(root, text="Enter Token:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    token_entry = tk.Entry(root, width=50)
    token_entry.pack(pady=5)
    
    def fetch_note():
        token = token_entry.get().strip()
        if not token:
            messagebox.showerror("Error", "Token cannot be empty!")
            return

        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT title, chacha_encrypted, aes_encrypted, signature, token,
                  (SELECT username FROM users WHERE id=notes.user_id) 
            FROM notes WHERE token=%s
        """, (token,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            messagebox.showerror("Error", "Invalid token or note does not exist!")
            return

        note_title, chacha_encrypted, aes_encrypted, signature, retrieved_token, note_owner = result

        # **Generate decryption key using the original note creator's username**
        key = generate_cipher_key(note_owner)

        try:
            decrypted_content_aes = decrypt_note_aes_gcm(key, aes_encrypted)

            conn = connect_to_db()
            cursor = conn.cursor()
            cursor.execute("SELECT public_key FROM users WHERE username=%s", (note_owner,))
            public_key_pem = cursor.fetchone()[0]
            conn.close()

            if not verify_signature(public_key_pem, signature, decrypted_content_aes):
                messagebox.showerror("Error", "Signature verification failed! The note might be tampered with.")
                return

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Failed to decrypt note! Error: {str(e)}")
            return

        # **Pass the retrieved token to be displayed**
        display_note_by_token(root, retrieved_token, note_title, decrypted_content_aes, note_owner, username)


    tk.Button(root, text="Fetch Note", font=("Arial", 12), bg=BTN_COLOR, fg=TEXT_COLOR, command=fetch_note).pack(pady=5)
    tk.Button(root, text="🔙 Back", bg="gray", fg=TEXT_COLOR, font=("Arial", 12), 
              command=lambda: main_menu(root, username)).pack(pady=5)




def display_note_by_token(root, token, title, decrypted_content, owner, username):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="View Note", font=("Arial", 14, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=10)
    tk.Label(root, text=f"Note by {owner}", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    tk.Label(root, text=f"Title: {title}", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=5)

    # **Show the Token for Copying**
    tk.Label(root, text="Token:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    token_entry = tk.Entry(root, width=50)
    token_entry.insert(0, token)
    token_entry.config(state="readonly")
    token_entry.pack(pady=5)

    def copy_token():
        pyperclip.copy(token)
        messagebox.showinfo("Copied", "Token copied to clipboard!")

    tk.Button(root, text="Copy Token", font=("Arial", 12), bg=BTN_COLOR, fg=TEXT_COLOR, command=copy_token).pack()

    # **Display Decrypted Note Content**
    tk.Label(root, text="Content:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    content_text = tk.Text(root, height=10, width=50)
    content_text.insert("1.0", decrypted_content)
    content_text.config(state="disabled")
    content_text.pack()

    # **Back Button**
    tk.Button(root, text="Back", font=("Arial", 12), bg="gray", fg=TEXT_COLOR, 
              command=lambda: view_notes_window(root, username)).pack()



def view_notes_window(root, username):
    for widget in root.winfo_children():
        widget.destroy()

    root.geometry("500x450")
    root.configure(bg=BG_COLOR)

    tk.Label(root, text="📜 Your Notes", font=("Arial", 18, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=20)

    listbox = tk.Listbox(root, width=50, height=10, font=("Arial", 14))
    listbox.pack(pady=10)

    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT note_id, title FROM notes WHERE user_id = (SELECT id FROM users WHERE username=%s)", (username,))
    notes = cursor.fetchall()
    conn.close()

    note_map = {}  # Map note titles to note IDs
    for note in notes:
        listbox.insert(tk.END, note[1])
        note_map[note[1]] = note[0]

    def view_selected_note():
        selected_index = listbox.curselection()
        if not selected_index:
            messagebox.showerror("❌ Error", "Please select a note to view!")
            return

        selected_title = listbox.get(selected_index[0])
        note_id = note_map[selected_title]  # Retrieve corresponding note_id

        display_note_content(root, username, note_id)  # Pass note_id to display function

    tk.Button(root, text="👁 View Note", bg=BTN_COLOR, fg=TEXT_COLOR, font=("Arial", 14, "bold"), width=20, height=2, 
              command=view_selected_note).pack(pady=5)
    
    tk.Button(root, text="🔙 Back", bg="gray", fg=TEXT_COLOR, font=("Arial", 12), 
              command=lambda: main_menu(root, username)).pack(pady=5)



    root.update_idletasks()

def display_note_content(root, username, note_id):
    for widget in root.winfo_children():
        widget.destroy()

    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute("SELECT chacha_encrypted, aes_encrypted, signature, token FROM notes WHERE note_id=%s", (note_id,))
    result = cursor.fetchone()
    conn.close()

    if not result:
        messagebox.showerror("Error", "Failed to retrieve the note!")
        return

    chacha_encrypted, aes_encrypted, signature, token = result
    key = generate_cipher_key(username)

    try:
        decrypted_content_aes = decrypt_note_aes_gcm(key, aes_encrypted)

        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username=%s", (username,))
        public_key_pem = cursor.fetchone()[0]
        conn.close()

        if not verify_signature(public_key_pem, signature, decrypted_content_aes):
            messagebox.showerror("Error", "Signature verification failed! The note might be tampered with.")
            return

    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt note! Error: {str(e)}")
        return

    # **Display UI for Note Content and Token**
    tk.Label(root, text="View Note", font=("Arial", 14, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=10)
    tk.Label(root, text="Content:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()

    content_text = tk.Text(root, height=10, width=50)
    content_text.insert("1.0", decrypted_content_aes)
    content_text.config(state="disabled")
    content_text.pack()

    # **Show the Token for Copying**
    tk.Label(root, text="Token:", font=("Arial", 12, "bold"), fg=TEXT_COLOR, bg=BG_COLOR).pack()
    token_entry = tk.Entry(root, width=50)
    token_entry.insert(0, token)
    token_entry.config(state="readonly")
    token_entry.pack(pady=5)

    def copy_token():
        pyperclip.copy(token)
        messagebox.showinfo("Copied", "Token copied to clipboard!")

    tk.Button(root, text="Copy Token", font=("Arial", 12), bg=BTN_COLOR, fg=TEXT_COLOR, command=copy_token).pack()

    # **Back Button**
    tk.Button(root, text="Back", font=("Arial", 12), bg="gray", fg=TEXT_COLOR, 
              command=lambda: view_notes_window(root, username)).pack()

def logout(root):
    """Logs out the user and returns to the login window."""
    root.destroy()  # Close the current session
    login_window()  # Redirect back to the login screen

if __name__ == "__main__":
    login_window()  # Ensure that the application starts from the login screen
