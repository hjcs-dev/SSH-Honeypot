import socket
import threading
import paramiko
from paramiko import RSAKey, ServerInterface, AUTH_SUCCESSFUL
import io
import requests
from colorama import init, Fore, Style
from pystyle import Colors, Colorate
import json

init(autoreset=True)

host_key = RSAKey.generate(2048)
WEBHOOK_URL = None
WELCOME_MESSAGE = "its a honeypot bro x)"

def get_ip_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/{ip}")
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return data
    except:
        pass
    return None

class HoneyPotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, transport):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.transport = transport
        self.username = None
        self.password = None
        self.client_version = None
        self.kex = None
        self.cipher = None
        self.compression = None
        self.mac = None
        self.os_info = None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        self.client_version = self.transport.remote_version if hasattr(self.transport, "remote_version") else "Unknown"
        sec_opts = self.transport.get_security_options()
        self.kex = ", ".join(sec_opts.kex) if hasattr(sec_opts, "kex") else "N/A"
        self.cipher = ", ".join(sec_opts.ciphers) if hasattr(sec_opts, "ciphers") else "N/A"
        self.mac = ", ".join(sec_opts.macs) if hasattr(sec_opts, "macs") else "N/A"
        self.compression = ", ".join(sec_opts.compressions) if hasattr(sec_opts, "compressions") else "N/A"

        ip_info = get_ip_info(self.client_ip)
        self.os_info = ip_info.get("isp") if ip_info else "Unknown ISP"

        print(Colorate.Vertical(Colors.blue_to_cyan, f"""
{Fore.GREEN}[+] Authentication attempt
{Fore.YELLOW}Username: {Fore.RESET}{self.username}
{Fore.YELLOW}Password: {Fore.RESET}{self.password}
{Fore.YELLOW}Client IP: {Fore.RESET}{self.client_ip}
{Fore.YELLOW}Client SSH Version: {Fore.RESET}{self.client_version}
{Fore.YELLOW}ISP / Org: {Fore.RESET}{self.os_info}

{Fore.YELLOW}Algorithms:
{Fore.YELLOW}- KEX: {Fore.RESET}{self.kex}
{Fore.YELLOW}- Ciphers: {Fore.RESET}{self.cipher}
{Fore.YELLOW}- MACs: {Fore.RESET}{self.mac}
{Fore.YELLOW}- Compression: {Fore.RESET}{self.compression}
"""))

        if WEBHOOK_URL:
            try:
                msg = f"**SSH Honeypot Alert**\n**Username:** `{username}`\n**Password:** `{password}`\n**IP:** `{self.client_ip}`\n**SSH Client:** `{self.client_version}`\n**ISP:** `{self.os_info}`\n\n**Algorithms:**\n- KEX: {self.kex}\n- Cipher: {self.cipher}\n- MAC: {self.mac}\n- Compression: {self.compression}"
                requests.post(WEBHOOK_URL, json={"content": msg})
            except Exception as e:
                print(Fore.RED + f"Webhook error: {e}")

        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

def handle_client(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    server = HoneyPotServer(addr[0], transport)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print(Fore.RED + "SSH negotiation failed")
        return

    chan = transport.accept(20)
    if chan is None:
        print(Fore.RED + "No channel request from client")
        return

    try:
        chan.send(WELCOME_MESSAGE)
        while True:
            data = chan.recv(1024)
            if not data:
                break
           
            chan.send("Command not recognized.\n")
    except Exception:
        pass
    finally:
        chan.close()
        transport.close()
        print(Fore.YELLOW + f"Connection closed: {addr[0]}")


def main():
    global WEBHOOK_URL
    banner = Colorate.Vertical(Colors.cyan_to_blue, r"""
  ██████   ██████  ██░ ██     ██░ ██  ▒█████   ███▄    █ ▓█████▓██   ██▓ ██▓███   ▒█████  ▄▄▄█████▓
▒██    ▒ ▒██    ▒ ▓██░ ██▒   ▓██░ ██▒▒██▒  ██▒ ██ ▀█   █ ▓█   ▀ ▒██  ██▒▓██░  ██▒▒██▒  ██▒▓  ██▒ ▓▒
░ ▓██▄   ░ ▓██▄   ▒██▀▀██░   ▒██▀▀██░▒██░  ██▒▓██  ▀█ ██▒▒███    ▒██ ██░▓██░ ██▓▒▒██░  ██▒▒ ▓██░ ▒░
  ▒   ██▒  ▒   ██▒░▓█ ░██    ░▓█ ░██ ▒██   ██░▓██▒  ▐▌██▒▒▓█  ▄  ░ ▐██▓░▒██▄█▓▒ ▒▒██   ██░░ ▓██▓ ░ 
▒██████▒▒▒██████▒▒░▓█▒░██▓   ░▓█▒░██▓░ ████▓▒░▒██░   ▓██░░▒████▒ ░ ██▒▓░▒██▒ ░  ░░ ████▓▒░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒    ▒ ░░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░░ ▒░ ░  ██▒▒▒ ▒▓▒░ ░  ░░ ▒░▒░▒░   ▒ ░░   
░ ░▒  ░ ░░ ░▒  ░ ░ ▒ ░▒░ ░    ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ░ ░  ░▓██ ░▒░ ░▒ ░       ░ ▒ ▒░     ░    
░  ░  ░  ░  ░  ░   ░  ░░ ░    ░  ░░ ░░ ░ ░ ▒     ░   ░ ░    ░   ▒ ▒ ░░  ░░       ░ ░ ░ ▒    ░      
      ░        ░   ░  ░  ░    ░  ░  ░    ░ ░           ░    ░  ░░ ░                  ░ ░           
                                                                ░ ░                                


                                                    
SSH Honeypot - Capture all credentials and info
""")
    print(banner)

    try:
        port = int(input("Listen on port (e.g. 2222): "))
    except:
        print(Fore.RED + "Invalid port")
        return

    wh = input("Discord Webhook URL (leave empty for console only): ").strip()
    if wh:
        WEBHOOK_URL = wh

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(100)
    print(Fore.YELLOW + f"Listening on port {port}...")

    try:
        while True:
            client, addr = sock.accept()
            print(Fore.MAGENTA + f"New connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        print(Fore.RED + "\nShutting down honeypot...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
