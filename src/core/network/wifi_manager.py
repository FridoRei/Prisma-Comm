# src/core/network/wifi_manager.py
import subprocess

def detectar_interfaces_wifi(): # Detecta as interfaces wireless controladas pelo NetworkManager
    result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"],
                             capture_output=True, text=True)
    interfaces = []
    for linha in result.stdout.splitlines():
        partes = linha.split(":")
        if len(partes) >= 3 and partes[1] == "wifi":
            interfaces.append(partes[0])
    return interfaces

def desconectar_interface(interface): # Desconecta a interface da rede conectada
    subprocess.run(["nmcli", "dev", "disconnect", interface])

def criar_hotspot(interface, ssid, senha): # cria o hotspot
    desconectar_interface(interface)
    subprocess.run(["nmcli", "dev", "wifi", "hotspot", "ifname", interface,
                    "ssid", ssid, "password", senha], check=True)

