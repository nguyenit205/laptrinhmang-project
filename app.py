"""
Secure QR File Transfer - Main Application
Hybrid Encryption: RSA + AES + Password Protection
"""
import io
import os
import uuid
import socket
import threading
import ssl
import numpy as np
import customtkinter as ctk
from customtkinter import filedialog
from PIL import Image, ImageTk
import cv2

from config import *
from encrypt_hybrid_rsa_password import (
    generate_password_protected_keypair,
    encrypt_file_hybrid,
    decrypt_file_hybrid,
    build_token,
    generate_qr,
    check_file_size
)
from chat_file_tcp_tls import TcpChatServer, TcpChatClient
from user_auth import UserAuth


# ==================== Preview Window ====================

class PreviewWindow(ctk.CTkToplevel):
    """Image preview popup"""
    def __init__(self, master, image_bytes: bytes, filename: str):
        super().__init__(master)
        self.title(f"Preview: {filename}")
        self.geometry("600x400")
        self.attributes("-topmost", True)
        
        img = Image.open(io.BytesIO(image_bytes))
        img.thumbnail((560, 340), Image.Resampling.LANCZOS)
        self.img_tk = ImageTk.PhotoImage(img)
        
        ctk.CTkLabel(self, image=self.img_tk, text="").pack(expand=True, fill="both", padx=10, pady=10)


# ==================== Emoji Picker ====================

class EmojiPicker(ctk.CTkToplevel):
    """Emoji selection popup"""
    EMOJIS = [
        "😊", "😂", "❤️", "👍", "🎉", "🔥", "✨", "💯",
        "😍", "🥰", "😘", "😭", "😢", "😡", "😎", "🤔",
        "👏", "🙏", "💪", "✅", "❌", "⭐", "🌟", "💝"
    ]
    
    def __init__(self, master, on_select):
        super().__init__(master)
        self.title("Select Emoji")
        self.geometry("340x200")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.on_select = on_select
        
        frame = ctk.CTkFrame(self)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        for i, emoji in enumerate(self.EMOJIS):
            btn = ctk.CTkButton(
                frame, text=emoji, width=40, height=40,
                font=("Segoe UI", 20),
                command=lambda e=emoji: self.select(e)
            )
            btn.grid(row=i//8, column=i%8, padx=2, pady=2)
    
    def select(self, emoji):
        self.on_select(emoji)
        self.destroy()


# ==================== Main Application ====================

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.auth = UserAuth()
        self.title(APP_TITLE)
        self.geometry(APP_GEOMETRY)
        self.minsize(*APP_MIN_SIZE)
        
        # State variables
        self.selected_file = None
        self.qr_original = None
        self.qr_imgtk = None
        self.decrypted_bytes = None
        self.decrypted_filename = None
        self.incoming_files = {}
        self.local_ip = "127.0.0.1"
        
        # Networking
        self.tcp_server = None
        self.tcp_client = None
        
        self._setup_ui()
    
    def _setup_ui(self):
        if not self.auth.is_logged_in():
            self.show_login_view()
        else:
            self._setup_main_app()
    
    # ==================== Auth Views ====================
    
    def show_login_view(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True, fill="both")
        
        card = ctk.CTkFrame(container, corner_radius=20, width=400)
        card.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(card, text="🔐 Secure QR File", font=("Segoe UI", 28, "bold")).pack(pady=(40, 10))
        ctk.CTkLabel(card, text="Login to your account", font=("Segoe UI", 14)).pack(pady=(0, 30))
        
        self.login_username = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Username")
        self.login_username.pack(pady=(0, 15), padx=40)
        
        self.login_password = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Password", show="●")
        self.login_password.pack(pady=(0, 10), padx=40)
        self.login_password.bind("<Return>", lambda e: self.do_login())
        
        ctk.CTkButton(card, text="Login", width=300, height=40, font=("Segoe UI", 14, "bold"), command=self.do_login).pack(pady=(10, 10), padx=40)
        
        self.login_status = ctk.CTkLabel(card, text="", font=("Segoe UI", 11), text_color="red")
        self.login_status.pack(pady=(5, 10))
        
        ctk.CTkFrame(card, height=1, fg_color="gray").pack(fill="x", padx=40, pady=15)
        
        bottom = ctk.CTkFrame(card, fg_color="transparent")
        bottom.pack(pady=(0, 30))
        ctk.CTkLabel(bottom, text="Don't have an account?", font=("Segoe UI", 12)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(bottom, text="Register", width=80, height=28, command=self.show_register_view).pack(side="left")
    
    def show_register_view(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True, fill="both")
        
        card = ctk.CTkFrame(container, corner_radius=20, width=400)
        card.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(card, text="Create Account", font=("Segoe UI", 26, "bold")).pack(pady=(40, 30))
        
        self.reg_username = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Username")
        self.reg_username.pack(pady=(0, 15), padx=40)
        
        self.reg_email = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Email")
        self.reg_email.pack(pady=(0, 15), padx=40)
        
        self.reg_password = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Password", show="●")
        self.reg_password.pack(pady=(0, 15), padx=40)
        
        self.reg_password_confirm = ctk.CTkEntry(card, width=300, height=40, placeholder_text="Confirm Password", show="●")
        self.reg_password_confirm.pack(pady=(0, 10), padx=40)
        self.reg_password_confirm.bind("<Return>", lambda e: self.do_register())
        
        ctk.CTkButton(card, text="Create Account", width=300, height=40, font=("Segoe UI", 14, "bold"), command=self.do_register).pack(pady=(10, 10), padx=40)
        
        self.register_status = ctk.CTkLabel(card, text="", font=("Segoe UI", 11), text_color="red")
        self.register_status.pack(pady=(5, 10))
        
        ctk.CTkFrame(card, height=1, fg_color="gray").pack(fill="x", padx=40, pady=15)
        
        bottom = ctk.CTkFrame(card, fg_color="transparent")
        bottom.pack(pady=(0, 30))
        ctk.CTkLabel(bottom, text="Already have an account?", font=("Segoe UI", 12)).pack(side="left", padx=(0, 5))
        ctk.CTkButton(bottom, text="Login", width=80, height=28, command=self.show_login_view).pack(side="left")
    
    def do_login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            self.login_status.configure(text="Please enter username and password", text_color="orange")
            return
        
        success, message = self.auth.login(username, password)
        
        if success:
            pub_path = os.path.join("keys", f"{username}_public.pem")
            priv_path = os.path.join("keys", f"{username}_private.enc")
            
            if not os.path.exists(pub_path) or not os.path.exists(priv_path):
                try:
                    generate_password_protected_keypair(password, username)
                except Exception as e:
                    self.login_status.configure(text=f"Keypair error: {e}", text_color="red")
                    return
            
            self.login_status.configure(text=message, text_color="green")
            self.after(500, self._setup_main_app)
        else:
            self.login_status.configure(text=message, text_color="red")
    
    def do_register(self):
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        password = self.reg_password.get()
        password_confirm = self.reg_password_confirm.get()
        
        if not username or not email or not password:
            self.register_status.configure(text="Please fill in all fields", text_color="orange")
            return
        
        if password != password_confirm:
            self.register_status.configure(text="Passwords do not match", text_color="red")
            return
        
        success, message = self.auth.create_account(username, email, password)
        
        if success:
            try:
                generate_password_protected_keypair(password, username)
                self.register_status.configure(text=f"{message}\n🔑 Keypair generated!", text_color="green")
                self.after(1500, self.show_login_view)
            except Exception as e:
                self.auth._delete_account(username)
                self.register_status.configure(text=f"Keypair failed: {e}", text_color="red")
        else:
            self.register_status.configure(text=message, text_color="red")
    
    # ==================== Main App ====================
    
    def _setup_main_app(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        self.title(f"{APP_TITLE} - {self.auth.get_current_user()}")
        
        # Get local IP
        try:
            hostname = socket.gethostname()
            self.local_ip = socket.gethostbyname(hostname)
        except:
            self.local_ip = "127.0.0.1"
        
        if self.tcp_server is None:
            self.tcp_server = TcpChatServer("0.0.0.0", LOCAL_PORT, self.on_tcp_text, self.on_tcp_file)
            self.tcp_server.start()
        
        if self.tcp_client is None:
            self.tcp_client = TcpChatClient()
        
        self._setup_sidebar()
        self._setup_main_frame()
    
    def _setup_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        
        user_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        user_frame.pack(pady=(20, 10), padx=20)
        ctk.CTkLabel(user_frame, text="👤", font=("Segoe UI", 24)).pack()
        ctk.CTkLabel(user_frame, text=self.auth.get_current_user(), font=("Segoe UI", 14, "bold")).pack()
        
        ctk.CTkLabel(sidebar, text="🔐 Secure QR File", font=("Segoe UI", 18, "bold")).pack(pady=(10, 20), padx=20)
        
        ctk.CTkButton(sidebar, text="Encrypt & Generate QR", command=self.show_encrypt_view).pack(padx=20, pady=(10, 10), fill="x")
        ctk.CTkButton(sidebar, text="Scan & Download", command=self.show_decrypt_view).pack(padx=20, pady=(0, 10), fill="x")
        ctk.CTkButton(sidebar, text="Chat & File Transfer", command=self.show_chat_view).pack(padx=20, pady=(0, 10), fill="x")
        
        ctk.CTkSwitch(sidebar, text="Light / Dark", command=self.toggle_theme).pack(padx=20, pady=(30, 10))
        ctk.CTkButton(sidebar, text="🚪 Logout", fg_color="red", hover_color="darkred", command=self.do_logout).pack(padx=20, pady=(10, 20), side="bottom")
    
    def _setup_main_frame(self):
        self.main = ctk.CTkFrame(self, corner_radius=15)
        self.main.pack(side="right", fill="both", expand=True, padx=15, pady=15)
        self.show_encrypt_view()
    
    def do_logout(self):
        self.auth.logout()
        if self.tcp_server:
            self.tcp_server.stop()
        self.show_login_view()
    
    def toggle_theme(self):
        mode = ctk.get_appearance_mode()
        ctk.set_appearance_mode("light" if mode == "Dark" else "dark")
    
    def clear_main(self):
        for w in self.main.winfo_children():
            w.destroy()
    
    # ==================== Encrypt View ====================
    
    def show_encrypt_view(self):
        self.clear_main()
        self.selected_file = None
        self.qr_original = None
        self.qr_imgtk = None
        
        ctk.CTkLabel(self.main, text="Encrypt & Generate QR", font=("Segoe UI", 22, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self.main, text="Hybrid Encryption: RSA + AES + Password", font=("Segoe UI", 12)).pack(pady=(0, 15))
        
        file_frame = ctk.CTkFrame(self.main, corner_radius=10)
        file_frame.pack(fill="x", padx=30, pady=10)
        
        self.file_label = ctk.CTkLabel(file_frame, text="No file selected...", anchor="w")
        self.file_label.pack(side="left", padx=15, pady=15, expand=True, fill="x")
        ctk.CTkButton(file_frame, text="Browse", width=120, command=self.choose_file).pack(side="right", padx=15, pady=15)
        
        ctk.CTkButton(self.main, text="🔒 Encrypt & Generate QR", height=40, command=self.encrypt_and_generate_qr).pack(pady=(20, 10))
        
        self.status_label = ctk.CTkLabel(self.main, text="", font=("Segoe UI", 12), justify="center")
        self.status_label.pack(pady=(5, 10))
        
        qr_frame = ctk.CTkFrame(self.main, corner_radius=10)
        qr_frame.pack(expand=True, fill="both", padx=40, pady=(5, 15))
        
        ctk.CTkLabel(qr_frame, text="QR Preview", font=("Segoe UI", 14, "bold")).pack(pady=(10, 5))
        
        self.qr_label = ctk.CTkLabel(qr_frame, text="No QR yet.\nEncrypt a file to generate QR.", justify="center")
        self.qr_label.pack(expand=True)
        
        self.save_qr_btn = ctk.CTkButton(qr_frame, text="Save QR as image", state="disabled", command=self.save_qr)
        self.save_qr_btn.pack(pady=(5, 15))
    
    def choose_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        
        try:
            valid, size = check_file_size(path)
        except OSError as e:
            self.status_label.configure(text=f"❌ Error: {e}")
            return
        
        if not valid:
            self.status_label.configure(text="❌ File too large (max 50 MB)")
            return
        
        self.selected_file = path
        self.file_label.configure(text=os.path.basename(path))
        self.status_label.configure(text="")
    
    def encrypt_and_generate_qr(self):
        if not self.selected_file:
            self.status_label.configure(text="⚠️ Please select a file first")
            return
        
        password_dialog = ctk.CTkInputDialog(text="Enter your account password:", title="Password Required")
        password = password_dialog.get_input()
        
        if not password:
            self.status_label.configure(text="⚠️ Password required")
            return
        
        username = self.auth.get_current_user().strip()
        if not self.auth.verify_password(username, password):
            self.status_label.configure(text="❌ Wrong password!")
            return
        
        try:
            file_id, _ = encrypt_file_hybrid(self.selected_file, username)
            token_str = build_token(file_id, os.path.basename(self.selected_file), username, username)
            qr_path, img = generate_qr(token_str, file_id)
            
            self.qr_original = img
            img_resized = img.copy()
            img_resized.thumbnail((320, 320), Image.Resampling.LANCZOS)
            self.qr_imgtk = ImageTk.PhotoImage(img_resized)
            self.qr_label.configure(image=self.qr_imgtk, text="")
            self.save_qr_btn.configure(state="normal")
            
            self.status_label.configure(text="✅ Encrypted!\n📤 Share QR code\n🔐 Receiver needs YOUR password")
        except Exception as e:
            self.status_label.configure(text=f"❌ Error: {e}")
    
    def save_qr(self):
        if not self.qr_original:
            return
        
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")])
        if path:
            try:
                self.qr_original.save(path)
                self.status_label.configure(text=f"✅ QR saved: {os.path.basename(path)}")
            except Exception as e:
                self.status_label.configure(text=f"❌ Error: {e}")
    
    # ==================== Decrypt View ====================
    
    def show_decrypt_view(self):
        self.clear_main()
        self.decrypted_bytes = None
        self.decrypted_filename = None
        
        ctk.CTkLabel(self.main, text="Scan & Download", font=("Segoe UI", 22, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self.main, text="Scan QR and enter sender's password", font=("Segoe UI", 12)).pack(pady=(0, 15))
        
        qr_frame = ctk.CTkFrame(self.main, corner_radius=10)
        qr_frame.pack(fill="x", padx=30, pady=10)
        
        ctk.CTkButton(qr_frame, text="Browse QR", width=140, command=self.choose_qr_image).pack(side="left", padx=15, pady=15)
        self.qr_path_label = ctk.CTkLabel(qr_frame, text="No QR selected...", anchor="w")
        self.qr_path_label.pack(side="left", padx=10, pady=15, expand=True, fill="x")
        
        pwd_frame = ctk.CTkFrame(self.main, corner_radius=10)
        pwd_frame.pack(fill="x", padx=30, pady=10)
        
        ctk.CTkLabel(pwd_frame, text="Password:").pack(side="left", padx=(15, 5), pady=15)
        self.decrypt_password_entry = ctk.CTkEntry(pwd_frame, width=200, show="●", placeholder_text="Sender's password")
        self.decrypt_password_entry.pack(side="left", padx=(0, 10), pady=15)
        ctk.CTkButton(pwd_frame, text="🔓 Decrypt", width=100, command=self.decrypt_with_password).pack(side="left", padx=(0, 15), pady=15)
        
        self.info_label = ctk.CTkLabel(self.main, text="", justify="center", font=("Segoe UI", 12))
        self.info_label.pack(pady=(10, 10))
        
        btn_frame = ctk.CTkFrame(self.main, corner_radius=10)
        btn_frame.pack(pady=(5, 10))
        
        self.view_btn = ctk.CTkButton(btn_frame, text="Preview", state="disabled", command=self.view_decrypted)
        self.view_btn.pack(side="left", padx=10, pady=10)
        self.download_btn = ctk.CTkButton(btn_frame, text="Download", state="disabled", command=self.download_decrypted)
        self.download_btn.pack(side="left", padx=10, pady=10)
        
        self.dec_status = ctk.CTkLabel(self.main, text="", justify="center", font=("Segoe UI", 11))
        self.dec_status.pack(pady=(5, 10))
    
    def choose_qr_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if not path:
            return
        
        self.qr_path_label.configure(text=os.path.basename(path))
        
        try:
            img = Image.open(path)
            img_array = np.array(img.convert('RGB'))
            img_cv = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            token_str, _, _ = cv2.QRCodeDetector().detectAndDecode(img_cv)
            
            if not token_str:
                self.info_label.configure(text="❌ No QR code found")
                return
            
            self.scanned_token = token_str
            
            import json
            obj = json.loads(token_str)
            self.info_label.configure(text=f"📄 {obj.get('filename')}\n👤 From: {obj.get('from')}\n⚠️ Enter password to decrypt")
        except Exception as e:
            self.info_label.configure(text=f"❌ Error: {e}")
    
    def decrypt_with_password(self):
        if not hasattr(self, 'scanned_token'):
            self.dec_status.configure(text="⚠️ Scan QR first")
            return
        
        password = self.decrypt_password_entry.get().strip()
        if not password:
            self.dec_status.configure(text="⚠️ Enter password")
            return
        
        try:
            data, filename = decrypt_file_hybrid(self.scanned_token, password)
            self.decrypted_bytes = data
            self.decrypted_filename = filename
            self.dec_status.configure(text="✅ Decrypted!")
            self.download_btn.configure(state="normal")
            
            if os.path.splitext(filename)[1].lower() in [".png", ".jpg", ".jpeg"]:
                self.view_btn.configure(state="normal")
        except Exception as e:
            self.dec_status.configure(text=f"❌ {e}")
    
    def view_decrypted(self):
        if self.decrypted_bytes and self.decrypted_filename:
            PreviewWindow(self, self.decrypted_bytes, self.decrypted_filename)
    
    def download_decrypted(self):
        if not self.decrypted_bytes:
            return
        
        path = filedialog.asksaveasfilename(initialfile=self.decrypted_filename, defaultextension="")
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(self.decrypted_bytes)
                self.dec_status.configure(text=f"✅ Saved: {os.path.basename(path)}")
            except Exception as e:
                self.dec_status.configure(text=f"❌ {e}")
    
    # ==================== Chat View ====================
    
    def show_chat_view(self):
        self.clear_main()
        
        ctk.CTkLabel(self.main, text="Chat & File Transfer (TLS)", font=("Segoe UI", 22, "bold")).pack(pady=(20, 5))
        
        # Top frame
        top = ctk.CTkFrame(self.main, corner_radius=10)
        top.pack(fill="x", padx=30, pady=5)
        
        # Server IP with copy button
        ip_frame = ctk.CTkFrame(top, fg_color="transparent")
        ip_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=(10, 5), sticky="w")
        
        ctk.CTkLabel(ip_frame, text=f"🌐 Your IP: {self.local_ip}:{LOCAL_PORT}", font=("Segoe UI", 12, "bold"), text_color="green").pack(side="left", padx=(0, 5))
        ctk.CTkButton(ip_frame, text="📋", width=40, height=24, command=self.copy_ip).pack(side="left")
        
        # Target IP with test button
        ctk.CTkLabel(top, text="Target IP:").grid(row=1, column=0, padx=(10, 5), pady=10, sticky="w")
        self.chat_ip_entry = ctk.CTkEntry(top, width=140, placeholder_text="e.g., 192.168.1.100")
        self.chat_ip_entry.grid(row=1, column=1, padx=(0, 5), pady=10, sticky="w")
        self.chat_ip_entry.insert(0, "127.0.0.1")
        
        self.connect_btn = ctk.CTkButton(top, text="🔌 Test", width=70, command=self.test_connection)
        self.connect_btn.grid(row=1, column=2, padx=(0, 10), pady=10, sticky="w")
        
        # Chat frame
        chat_frame = ctk.CTkFrame(self.main, corner_radius=10)
        chat_frame.pack(expand=True, fill="both", padx=30, pady=(5, 10))
        self.chat_scroll = ctk.CTkScrollableFrame(chat_frame, corner_radius=10)
        self.chat_scroll.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Input frame
        bottom = ctk.CTkFrame(self.main, corner_radius=10)
        bottom.pack(fill="x", padx=30, pady=(0, 15))
        
        ctk.CTkButton(bottom, text="😊", width=40, font=("Segoe UI", 18), command=self.open_emoji_picker).pack(side="left", padx=(10, 5), pady=10)
        self.chat_input = ctk.CTkEntry(bottom, placeholder_text="Type a message...")
        self.chat_input.pack(side="left", padx=(0, 5), pady=10, fill="x", expand=True)
        self.chat_input.bind("<Return>", lambda e: self.send_chat_text())
        ctk.CTkButton(bottom, text="📤", width=60, command=self.send_chat_text).pack(side="left", padx=(5, 5), pady=10)
        ctk.CTkButton(bottom, text="📎", width=60, command=self.send_tcp_file).pack(side="left", padx=(5, 10), pady=10)
        
        # Welcome messages
        self.add_chat_row(f"[SYSTEM] Chat as {self.auth.get_current_user()}", True)
        self.add_chat_row(f"[SYSTEM] Share IP: {self.local_ip}", True)
    
    def copy_ip(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(f"{self.local_ip}:{LOCAL_PORT}")
            self.add_chat_row("[SYSTEM] 📋 IP copied!", True)
        except:
            pass
    
    def test_connection(self):
        ip = self.chat_ip_entry.get().strip()
        if not ip:
            self.add_chat_row("[SYSTEM] ⚠️ Enter IP", True)
            return
        
        self.connect_btn.configure(state="disabled", text="...")
        threading.Thread(target=self._do_test, args=(ip,), daemon=True).start()
    
    def _do_test(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            secure = ssl_ctx.wrap_socket(sock, server_hostname=ip)
            secure.connect((ip, LOCAL_PORT))
            secure.close()
            
            self.after(0, self._test_result, f"[SYSTEM] ✅ Connected to {ip}", True)
        except Exception as e:
            self.after(0, self._test_result, f"[SYSTEM] ❌ Failed: {e}", False)
    
    def _test_result(self, msg, success):
        self.add_chat_row(msg, True)
        color = "green" if success else "red"
        text = "✅" if success else "❌"
        self.connect_btn.configure(state="normal", text=text, fg_color=color)
        self.after(2000, lambda: self.connect_btn.configure(text="🔌 Test", fg_color=["#3B8ED0", "#1F6AA5"]))
    
    def open_emoji_picker(self):
        if self.chat_input:
            EmojiPicker(self, self.insert_emoji)
    
    def insert_emoji(self, emoji):
        if self.chat_input:
            self.chat_input.insert(self.chat_input.index("insert"), emoji)
    
    def add_chat_row(self, text, is_system=False):
        if not self.chat_scroll:
            return
        row = ctk.CTkFrame(self.chat_scroll, corner_radius=8)
        row.pack(fill="x", padx=5, pady=3)
        ctk.CTkLabel(row, text=text, anchor="w", text_color="#FFD700" if is_system else None, wraplength=600).pack(side="left", padx=6, pady=4, fill="x", expand=True)
    
    def add_file_row(self, from_text, file_id, filename, size):
        if not self.chat_scroll:
            return
        row = ctk.CTkFrame(self.chat_scroll, corner_radius=8)
        row.pack(fill="x", padx=5, pady=3)
        ctk.CTkLabel(row, text=f"{from_text} 📎 {filename} ({size} B)", anchor="w", wraplength=550).pack(side="left", padx=6, pady=4, fill="x", expand=True)
        ctk.CTkButton(row, text="⬇", width=32, height=28, command=lambda: self.download_incoming_file(file_id)).pack(side="right", padx=6, pady=4)
    
    def send_chat_text(self):
        if not self.chat_input:
            return
        msg = self.chat_input.get().strip()
        if not msg:
            return
        
        ip = self.chat_ip_entry.get().strip()
        if not ip:
            self.add_chat_row("[SYSTEM] Enter IP", True)
            return
        
        try:
            self.tcp_client.send_text(msg, ip, LOCAL_PORT)
            self.add_chat_row(f"You: {msg}")
            self.chat_input.delete(0, "end")
        except Exception as e:
            self.add_chat_row(f"[SYSTEM] Error: {e}", True)
    
    def on_tcp_text(self, text, addr):
        self.after(0, self.add_chat_row, f"{addr[0]}: {text}")
    
    def send_tcp_file(self):
        ip = self.chat_ip_entry.get().strip()
        if not ip:
            self.add_chat_row("[SYSTEM] Enter IP", True)
            return
        
        path = filedialog.askopenfilename()
        if not path:
            return
        
        try:
            size = os.path.getsize(path)
            if size > TCP_MAX_FILE_SIZE:
                self.add_chat_row("[SYSTEM] File too large (max 20MB)", True)
                return
            
            self.tcp_client.send_file(path, ip, LOCAL_PORT)
            self.add_file_row("You sent", str(uuid.uuid4()), os.path.basename(path), size)
        except Exception as e:
            self.add_chat_row(f"[SYSTEM] Error: {e}", True)
    
    def on_tcp_file(self, data, filename, addr):
        file_id = str(uuid.uuid4())
        self.incoming_files[file_id] = {"filename": filename, "bytes": data}
        self.after(0, self.add_file_row, f"{addr[0]} sent", file_id, filename, len(data))
    
    def download_incoming_file(self, file_id):
        info = self.incoming_files.get(file_id)
        if not info:
            self.add_chat_row("[SYSTEM] File not found", True)
            return
        
        path = filedialog.asksaveasfilename(initialfile=info["filename"])
        if path:
            try:
                with open(path, "wb") as f:
                    f.write(info["bytes"])
                self.add_chat_row(f"[SYSTEM] Saved to: {path}", True)
            except Exception as e:
                self.add_chat_row(f"[SYSTEM] Error: {e}", True)