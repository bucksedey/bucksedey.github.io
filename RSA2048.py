import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os

def load_public_key():
    filepath = filedialog.askopenfilename(
        filetypes=[("PEM Files", "*.pem")], 
        title="Selecciona la llave pública de Betito"
    )
    if filepath:
        with open(filepath, "rb") as public_file:
            return load_pem_public_key(public_file.read())
    else:
        raise ValueError("No se seleccionó ninguna llave pública.")

def load_private_key():
    filepath = filedialog.askopenfilename(
        filetypes=[("PEM Files", "*.pem")], 
        title="Selecciona TU llave privada"
    )
    if filepath:
        with open(filepath, "rb") as private_file:
            return load_pem_private_key(private_file.read(), password=None)
    else:
        raise ValueError("No se seleccionó ninguna llave privada.")

def encrypt_file(filepath):
    try:
        public_key = load_public_key()
        with open(filepath, "rb") as file:
            plaintext = file.read()
        
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Guardar archivo cifrado
        filename = os.path.basename(filepath)
        encrypted_path = filedialog.asksaveasfilename(
            defaultextension=".rsac",
            filetypes=[("Encrypted Files", "*.rsac")],
            title="Guardar archivo cifrado",
            initialfile=f"{os.path.splitext(filename)[0]}_cifrado.rsac"
        )
        
        if encrypted_path:
            with open(encrypted_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            messagebox.showinfo("Cifrado Exitoso", f"Archivo cifrado guardado:\n{encrypted_path}\n\nEnvíale este archivo a Betito")
    except Exception as e:
        messagebox.showerror("Error", f"Error durante el cifrado:\n{str(e)}")

def decrypt_file(filepath):
    try:
        private_key = load_private_key()
        with open(filepath, "rb") as file:
            ciphertext = file.read()
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Guardar archivo descifrado
        filename = os.path.basename(filepath)
        decrypted_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Guardar archivo descifrado",
            initialfile=f"{os.path.splitext(filename)[0]}_descifrado.txt"
        )
        
        if decrypted_path:
            with open(decrypted_path, "wb") as decrypted_file:
                decrypted_file.write(plaintext)
            messagebox.showinfo("Descifrado Exitoso", f"Archivo descifrado guardado:\n{decrypted_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Error durante el descifrado:\n{str(e)}\n\nPosibles causas:\n1. El archivo fue alterado\n2. Usaste la llave incorrecta\n3. El archivo no está cifrado")

def select_file(action):
    filepath = filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt")] if action == "encrypt" else [("Encrypted Files", "*.rsac")],
        title="Selecciona un archivo a cifrar" if action == "encrypt" else "Selecciona un archivo cifrado"
    )
    if filepath:
        if action == "encrypt":
            encrypt_file(filepath)
        elif action == "decrypt":
            decrypt_file(filepath)

def main():
    root = tk.Tk()
    root.title("Cifrado/Descifrado RSA 2048 - Práctica Criptografía")
    root.geometry("500x300")

    # Estilos
    root.configure(bg="#f0f2f5")
    title_font = ("Helvetica", 16, "bold")
    button_font = ("Helvetica", 12)
    
    # Marco principal
    main_frame = tk.Frame(root, bg="#f0f2f5", padx=20, pady=20)
    main_frame.pack(expand=True, fill="both")
    
    # Título
    tk.Label(
        main_frame, 
        text="Cifrado/Descifrado con RSA 2048", 
        font=title_font, 
        bg="#f0f2f5",
        fg="#2c3e50"
    ).pack(pady=(0, 20))
    
    # Explicación
    explanation = (
        "Instrucciones:\n"
        "1. Alicia: Cifra un mensaje con la llave pública de Betito\n"
        "2. Betito: Descifra el mensaje con tu llave privada\n"
        "3. Candy: Intenta interceptar y modificar mensajes"
    )
    tk.Label(
        main_frame, 
        text=explanation,
        bg="#f0f2f5",
        justify="left",
        wraplength=450
    ).pack(pady=(0, 20))
    
    # Botones
    btn_frame = tk.Frame(main_frame, bg="#f0f2f5")
    btn_frame.pack(pady=10)
    
    encrypt_btn = tk.Button(
        btn_frame, 
        text="Cifrar Archivo (Alicia)", 
        command=lambda: select_file("encrypt"), 
        font=button_font,
        bg="#3498db",
        fg="white",
        padx=15,
        pady=10
    )
    encrypt_btn.grid(row=0, column=0, padx=10, pady=5)
    
    decrypt_btn = tk.Button(
        btn_frame, 
        text="Descifrar Archivo (Betito)", 
        command=lambda: select_file("decrypt"), 
        font=button_font,
        bg="#2ecc71",
        fg="white",
        padx=15,
        pady=10
    )
    decrypt_btn.grid(row=0, column=1, padx=10, pady=5)
    
    # Nota
    tk.Label(
        main_frame, 
        text="Nota: Para la práctica, muestra cómo Candy puede interceptar y modificar archivos",
        bg="#f0f2f5",
        fg="#e74c3c",
        wraplength=450
    ).pack(pady=(20, 0))

    root.mainloop()

if __name__ == "__main__":
    main()