import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import hmac
from PIL import Image, ImageTk
import base64
from io import BytesIO
import hashpumpy
from colorama import Fore, Style
import server
import server_secure
import os

class MACAttackGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Attack Demonstration")
        self.root.geometry("800x700")
        self.root.configure(bg='white')

        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)

        # Create the three main tabs
        self.vuln_server_tab = ttk.Frame(self.notebook)
        self.secure_server_tab = ttk.Frame(self.notebook)
        self.attack_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.vuln_server_tab, text='Unsafe Server')
        self.notebook.add(self.secure_server_tab, text='Safe Server')
        self.notebook.add(self.attack_tab, text='Length Extension Attack')

        # Setup all tabs
        self.setup_vuln_server_tab()
        self.setup_secure_server_tab()
        self.setup_attack_tab()

    def setup_vuln_server_tab(self):
        # Header
        ttk.Label(self.vuln_server_tab, text="UNSAFE SERVER", 
                 font=('Helvetica', 16, 'bold'), foreground='red').pack(pady=10)
        
        # Original Message Frame
        msg_frame = ttk.LabelFrame(self.vuln_server_tab, text="Original Message")
        msg_frame.pack(pady=10, padx=10, fill="x")
        
        self.vuln_msg_var = tk.StringVar(value="amount=100&to=alice")
        ttk.Label(msg_frame, text="Message:").pack(pady=5)
        ttk.Entry(msg_frame, textvariable=self.vuln_msg_var, width=50).pack(pady=5)
        
        button_frame = ttk.Frame(msg_frame)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text="Get MAC", command=self.get_vuln_mac).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_vuln_tab).pack(side=tk.LEFT, padx=5)
        
        # MAC Display
        mac_frame = ttk.LabelFrame(self.vuln_server_tab, text="Server Response")
        mac_frame.pack(pady=10, padx=10, fill="x")
        
        self.vuln_mac_var = tk.StringVar()
        ttk.Label(mac_frame, text="MAC:").pack(pady=5)
        mac_entry = ttk.Entry(mac_frame, textvariable=self.vuln_mac_var, width=50, state='readonly')
        mac_entry.pack(pady=5)
        
        # Verification Frame
        verify_frame = ttk.LabelFrame(self.vuln_server_tab, text="Verify Forged Message")
        verify_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(verify_frame, text="Forged Message:").pack(pady=5)
        self.vuln_forged_msg = tk.Text(verify_frame, height=4, width=50)
        self.vuln_forged_msg.pack(pady=5)
        
        ttk.Label(verify_frame, text="Forged MAC:").pack(pady=5)
        self.vuln_forged_mac = tk.StringVar()
        ttk.Entry(verify_frame, textvariable=self.vuln_forged_mac, width=50).pack(pady=5)
        
        ttk.Button(verify_frame, text="Verify", command=self.verify_vuln).pack(pady=10)
        
        # Results
        self.vuln_result = tk.Text(self.vuln_server_tab, height=6, width=60)
        self.vuln_result.pack(pady=10, padx=10)

    def setup_secure_server_tab(self):
        # Header
        ttk.Label(self.secure_server_tab, text="SAFE SERVER", 
                 font=('Helvetica', 16, 'bold'), foreground='green').pack(pady=10)
        
        # Original Message Frame
        msg_frame = ttk.LabelFrame(self.secure_server_tab, text="Original Message")
        msg_frame.pack(pady=10, padx=10, fill="x")
        
        self.secure_msg_var = tk.StringVar(value="amount=100&to=alice")
        ttk.Label(msg_frame, text="Message:").pack(pady=5)
        ttk.Entry(msg_frame, textvariable=self.secure_msg_var, width=50).pack(pady=5)
        
        button_frame = ttk.Frame(msg_frame)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text="Get HMAC", command=self.get_secure_mac).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_secure_tab).pack(side=tk.LEFT, padx=5)
        
        # HMAC Display
        mac_frame = ttk.LabelFrame(self.secure_server_tab, text="Server Response")
        mac_frame.pack(pady=10, padx=10, fill="x")
        
        self.secure_mac_var = tk.StringVar()
        ttk.Label(mac_frame, text="HMAC:").pack(pady=5)
        mac_entry = ttk.Entry(mac_frame, textvariable=self.secure_mac_var, width=50, state='readonly')
        mac_entry.pack(pady=5)
        
        # Verification Frame
        verify_frame = ttk.LabelFrame(self.secure_server_tab, text="Verify Forged Message")
        verify_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(verify_frame, text="Forged Message:").pack(pady=5)
        self.secure_forged_msg = tk.Text(verify_frame, height=4, width=50)
        self.secure_forged_msg.pack(pady=5)
        
        ttk.Label(verify_frame, text="Forged MAC:").pack(pady=5)
        self.secure_forged_mac = tk.StringVar()
        ttk.Entry(verify_frame, textvariable=self.secure_forged_mac, width=50).pack(pady=5)
        
        ttk.Button(verify_frame, text="Verify", command=self.verify_secure).pack(pady=10)
        
        # Results
        self.secure_result = tk.Text(self.secure_server_tab, height=6, width=60)
        self.secure_result.pack(pady=10, padx=10)

    def setup_attack_tab(self):
        # Header
        ttk.Label(self.attack_tab, text="LENGTH EXTENSION ATTACK", 
                 font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        # Input Frame
        input_frame = ttk.LabelFrame(self.attack_tab, text="Attack Input")
        input_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(input_frame, text="Original Message:").pack(pady=5)
        self.attack_orig_msg = tk.StringVar(value="amount=100&to=alice")
        ttk.Entry(input_frame, textvariable=self.attack_orig_msg, width=50).pack(pady=5)
        
        ttk.Label(input_frame, text="Original MAC:").pack(pady=5)
        self.attack_orig_mac = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.attack_orig_mac, width=50).pack(pady=5)
        
        ttk.Label(input_frame, text="Payload to Append:").pack(pady=5)
        self.attack_payload = tk.StringVar(value="&admin=true")
        ttk.Entry(input_frame, textvariable=self.attack_payload, width=50).pack(pady=5)
        
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(pady=5)
        ttk.Button(button_frame, text="Generate Forged Message", 
                  command=self.perform_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_attack_tab).pack(side=tk.LEFT, padx=5)
        
        # Results Frame
        results_frame = ttk.LabelFrame(self.attack_tab, text="Attack Results")
        results_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.attack_result = tk.Text(results_frame, height=10, width=60)
        self.attack_result.pack(pady=10, padx=10, fill="both", expand=True)

    def get_vuln_mac(self):
        try:
            message = self.vuln_msg_var.get().encode()
            mac = server.generate_mac(message)
            self.vuln_mac_var.set(mac)
            
            self.vuln_result.delete(1.0, tk.END)
            self.vuln_result.insert(tk.END, "=== Original Message & MAC ===\n")
            self.vuln_result.insert(tk.END, f"Message: {message.decode()}\n")
            self.vuln_result.insert(tk.END, f"MAC: {mac}\n")
            
            # Auto-fill the attack tab
            self.attack_orig_msg.set(message.decode())
            self.attack_orig_mac.set(mac)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate MAC: {str(e)}")

    def get_secure_mac(self):
        try:
            message = self.secure_msg_var.get().encode()
            mac = server_secure.generate_mac(message)
            self.secure_mac_var.set(mac)
            
            self.secure_result.delete(1.0, tk.END)
            self.secure_result.insert(tk.END, "=== Original Message & HMAC ===\n")
            self.secure_result.insert(tk.END, f"Message: {message.decode()}\n")
            self.secure_result.insert(tk.END, f"HMAC: {mac}\n")
            
            # Auto-fill the attack tab
            self.attack_orig_msg.set(message.decode())
            self.attack_orig_mac.set(mac)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate HMAC: {str(e)}")

    def perform_attack(self):
        try:
            orig_message = self.attack_orig_msg.get().encode()
            orig_mac = self.attack_orig_mac.get()
            append_data = self.attack_payload.get().encode()
            
            if not orig_mac:
                messagebox.showwarning("Warning", "Please get the original MAC first!")
                return
            
            new_mac, new_message = hashpumpy.hashpump(
                orig_mac,
                orig_message,
                append_data,
                14  # Length of 'supersecretkey'
            )
            
            self.attack_result.delete(1.0, tk.END)
            self.attack_result.insert(tk.END, "=== Attack Results ===\n")
            self.attack_result.insert(tk.END, f"Original Message: {orig_message.decode()}\n")
            self.attack_result.insert(tk.END, f"Original MAC: {orig_mac}\n\n")
            self.attack_result.insert(tk.END, f"Forged Message (hex):\n{new_message.hex()}\n")
            self.attack_result.insert(tk.END, f"Forged Message (raw):\n{new_message.decode('latin1')}\n")
            self.attack_result.insert(tk.END, f"Forged MAC: {new_mac}\n")
            
            # Auto-fill the verification fields in both server tabs
            self.vuln_forged_msg.delete(1.0, tk.END)
            self.vuln_forged_msg.insert(1.0, new_message.decode('latin1'))
            self.vuln_forged_mac.set(new_mac)
            
            self.secure_forged_msg.delete(1.0, tk.END)
            self.secure_forged_msg.insert(1.0, new_message.decode('latin1'))
            self.secure_forged_mac.set(new_mac)
            
        except Exception as e:
            messagebox.showerror("Error", f"Attack failed: {str(e)}")

    def verify_vuln(self):
        try:
            message = self.vuln_forged_msg.get(1.0, tk.END).strip().encode('latin1')
            mac = self.vuln_forged_mac.get()
            
            self.vuln_result.delete(1.0, tk.END)
            self.vuln_result.insert(tk.END, "=== Verification Results ===\n")
            self.vuln_result.insert(tk.END, f"Message: {message.decode('latin1')}\n")
            self.vuln_result.insert(tk.END, f"MAC: {mac}\n\n")
            
            if server.verify(message, mac):
                self.vuln_result.insert(tk.END, "✅ Attack Successful!\n")
                self.vuln_result.insert(tk.END, "The unsafe server accepted the forged message!\n")
            else:
                self.vuln_result.insert(tk.END, "❌ Attack Failed\n")
                self.vuln_result.insert(tk.END, "The server rejected the forged message\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")

    def verify_secure(self):
        try:
            message = self.secure_forged_msg.get(1.0, tk.END).strip().encode('latin1')
            mac = self.secure_forged_mac.get()
            
            self.secure_result.delete(1.0, tk.END)
            self.secure_result.insert(tk.END, "=== Verification Results ===\n")
            self.secure_result.insert(tk.END, f"Message: {message.decode('latin1')}\n")
            self.secure_result.insert(tk.END, f"MAC: {mac}\n\n")
            
            if server_secure.verify(message, mac):
                self.secure_result.insert(tk.END, "⚠️ Unexpected: Attack Succeeded!\n")
                self.secure_result.insert(tk.END, "The secure server accepted the forged message!\n")
            else:
                self.secure_result.insert(tk.END, "✅ Attack Blocked\n")
                self.secure_result.insert(tk.END, "The HMAC protection prevented the attack!\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")

    def clear_vuln_tab(self):
        """Clear all fields in the vulnerable server tab"""
        self.vuln_msg_var.set("")
        self.vuln_mac_var.set("")
        self.vuln_forged_msg.delete(1.0, tk.END)
        self.vuln_forged_mac.set("")
        self.vuln_result.delete(1.0, tk.END)

    def clear_secure_tab(self):
        """Clear all fields in the secure server tab"""
        self.secure_msg_var.set("")
        self.secure_mac_var.set("")
        self.secure_forged_msg.delete(1.0, tk.END)
        self.secure_forged_mac.set("")
        self.secure_result.delete(1.0, tk.END)

    def clear_attack_tab(self):
        """Clear all fields in the attack tab"""
        self.attack_orig_msg.set("")
        self.attack_orig_mac.set("")
        self.attack_payload.set("")
        self.attack_result.delete(1.0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = MACAttackGUI(root)
    root.mainloop() 