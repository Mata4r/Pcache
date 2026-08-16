<a>
  <img src="https://i.postimg.cc/504HFJDK/D0F13209-3420-45F7-B59D-8F8158FC7492.png" width="200">
</a>

![Static Badge](https://img.shields.io/badge/github-Pcache-purple?logo=github)
![Static Badge](https://img.shields.io/badge/Docker-containing-grey?labelColor=2496ED&logo=docker&logoColor=white)

![Static Badge](https://img.shields.io/badge/Python-3.12-purple?labelColor=grey&logo=python&logoColor=white)
![Static Badge](https://img.shields.io/badge/Networking-purple?style=flat)

# Pcache

Pcache is a lightweight Python-based network scanner that focuses on passive scans.

## Features
- ARP-based network scan
- Passive network discovery
- MAC vendor lookup
- Local system information reporting
- Adjustable scan timing options
- Results saving

## Usage
Run the scanner from the project root:

`python pcache.py -As 192.168.1.0/24`

`python pcache.py -Ps 192.168.1.0/24 -i "Interface"`

`python pcache.py -V 00:1A:2B:3C:4D:5E`

`python pcache.py -info`

### Note

- Applying an Ip Address in a MAC vendor lookup well work but will cause ARP packet being sent to the Ip Address.

- It is preferable to use a MAC address if available.

# Windows installation

- Run CMD as administrator
```bash
git clone https://github.com/Mata4r/Pcache.git
```
```bash
cd Pcache
```
```bash
pip install -r requirements.txt
```

## Windows setup notes

- `scapy` on Windows requires an Npcap-compatible packet driver (Npcap). Install Npcap from https://nmap.org/npcap/ and enable "Support raw 802.11 traffic" only if you need wireless capture.
- Run scans from an elevated (Administrator) PowerShell/Command Prompt so raw packet operations work correctly.

# Linux installation
```bash
git clone https://github.com/Mata4r/Pcache.git
```
```bash
cd Pcache
```
```bash
sudo python3 -m pip install -r requirements.txt
```

## Notes
- This project is intended for authorized network analysis and learning purposes.
- Some features may require appropriate permissions depending on your environment.
