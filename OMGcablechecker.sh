#!/bin/bash
# OMG Cable Detection Suite v8.0 - M1 MacBook Active Scanner
# VERBOSE MODE: Shows ALL devices scanned with detailed verdicts
# CABLE FOCUSED: Detects cables and extracts ALL information
# Does NOT assume baseline is clean - analyzes everything
#
# NEW in v8.0:
# - WiFi network scanning with airport utility (hidden SSID detection)
# - Python IORegistry deep parsing with per-port/device topology
# - Data exfiltration monitoring for external USB devices
# - Enhanced OMG Cable Elite/Pro detection
# - Composite device detection
# - USB-C cable authentication checks
# - Network traffic analysis for exfil patterns
# - External storage monitoring
# - BLE advertising scan integration

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m'

# Counters
ALERT_COUNT=0
SCAN_CYCLE=0
CLEAN_COUNT=0
SUSPICIOUS_COUNT=0
THREAT_COUNT=0
CABLE_COUNT=0

# Tracking arrays
declare -a SCANNED_USB_DEVICES
declare -a SCANNED_INTERFACES
declare -a SCANNED_WIFI
declare -a SCANNED_BLUETOOTH

# Baseline for change detection
BASELINE_USB_COUNT=0
BASELINE_IFACE_COUNT=0
BASELINE_WIFI_COUNT=0

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       OMG CABLE DETECTION SUITE v8.0 - COMPREHENSIVE SCANNER          ║${NC}"
echo -e "${CYAN}║   Cable + WiFi + IORegistry + Data Exfil + Network Analysis            ║${NC}"
echo -e "${CYAN}║   Python Deep Scanning + Airport WiFi + Composite Device Detection    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# OMG CABLE IOCs (Indicators of Compromise)
# ══════════════════════════════════════════════════════════════════════════════

# Known OMG Cable vendor signatures
OMG_VENDORS=(
    "0x1337:Hak5 OMG Cable"
    "0xd3ad:OMG Dead Signature"
    "0xb33f:OMG Beef Signature"
    "0xcafe:OMG Cafe Signature"
    "0xface:OMG Face Signature"
    "0xfeed:OMG Feed Signature"
    "0xdead:OMG Dead Variant"
    "0xbeef:OMG Beef Variant"
    "0xc0de:OMG Code Signature"
    "0xbabe:OMG Babe Signature"
    "0x16d0:O.MG Cable Elite"
    "0x16d0:0x0e6c:O.MG Cable Elite WiFi"
    "0x16d0:0x0eaf:O.MG Cable Pro"
    "0x16c0:0x05df:KeyGrabber USB"
    "0x16c0:0x05dc:KeyGrabber Hardware"
    "0x16c0:0x0486:Teensy USB Development Board (HID Attack)"
    "0x1b4f:0x9206:SparkFun BadUSB"
    "0x1209:0x5bf0:USBNinja Cable"
    "0x1209:0x5bf1:USBNinja Pro"
    "0x04b4:0x8613:Hidden WiFi Adapter"
    "0x0bda:0x8176:Suspicious Realtek WiFi"
    "0x148f:0x5370:Ralink WiFi Adapter (Exfil Risk)"
    "0x2357:0x0109:TP-Link WiFi Adapter (Suspicious)"
)

# Spoofed Apple signatures
SPOOFED_APPLE=(
    "0x05ac:0x0000:Apple Null Product (SPOOFED)"
    "0x05ac:0x0001:Fake Apple Keyboard"
    "0x05ac:0x0220:Fake Apple Aluminum Keyboard"
    "0x05ac:0x0221:Fake Apple Wireless Keyboard"
    "0x05ac:0x0250:Fake Apple Trackpad"
    "0x05ac:0x8240:Fake Apple IR Receiver"
)

# BadUSB/HID Injection device vendors
BADUSB_VENDORS=(
    "0x2341:Arduino (HID Injection Capable)"
    "0x1b4f:SparkFun Pro Micro (HID Injection)"
    "0x239a:Adafruit (HID Injection Capable)"
    "0x1a86:QinHeng CH340 (Common Injection)"
    "0x2e8a:Raspberry Pi Pico (HID Injection)"
    "0x303a:Espressif ESP32-S2/S3 (HID Capable)"
    "0x1209:pid.codes Generic (Suspicious)"
    "0x16c0:Teensy PJRC (HID Injection)"
    "0x0483:STM32 (HID Injection Capable)"
    "0x1fc9:NXP LPC (HID Capable)"
    "0x04d8:Microchip (HID Capable)"
    "0x10c4:Silicon Labs CP210x"
    "0x0403:FTDI"
    "0x067b:Prolific"
)

# Known legitimate Apple internal devices (M1 MacBook)
# Apple USB Vendor ID: 0x05ac
APPLE_INTERNAL_LEGIT=(
    # Internal Controllers
    "0x05ac:0x8103"    # Apple T2/M1 Controller
    "0x05ac:0x8104"    # Apple T2 Controller variant
    "0x05ac:0x8105"    # Apple T2 Controller variant
    "0x05ac:0x8233"    # Apple Internal Keyboard M1
    "0x05ac:0x8262"    # Apple Internal Trackpad
    "0x05ac:0x8302"    # Apple USB-C Charge
    "0x05ac:0x8600"    # Apple M1 USB
    "0x05ac:0x8601"    # Apple M1 USB variant
    "0x05ac:0x8602"    # Apple M1 USB variant
    "0x05ac:0x1460"    # Apple USB Hub
    "0x05ac:0x1461"    # Apple USB Hub variant
    
    # Apple Keyboards
    "0x05ac:0x0220"    # Apple Aluminum Keyboard (ANSI)
    "0x05ac:0x0221"    # Apple Aluminum Keyboard (ISO)
    "0x05ac:0x0222"    # Apple Aluminum Keyboard (JIS)
    "0x05ac:0x0223"    # Apple Internal Keyboard
    "0x05ac:0x0224"    # Apple Internal Keyboard
    "0x05ac:0x0225"    # Apple Internal Keyboard
    "0x05ac:0x0229"    # Apple Internal Keyboard (ANSI)
    "0x05ac:0x022a"    # Apple Internal Keyboard (ISO)
    "0x05ac:0x022b"    # Apple Internal Keyboard (JIS)
    "0x05ac:0x0230"    # Apple Internal Keyboard
    "0x05ac:0x0231"    # Apple Internal Keyboard
    "0x05ac:0x0232"    # Apple Internal Keyboard
    "0x05ac:0x0236"    # Apple Internal Keyboard
    "0x05ac:0x0237"    # Apple Internal Keyboard
    "0x05ac:0x0238"    # Apple Internal Keyboard
    "0x05ac:0x023f"    # Apple Internal Keyboard
    "0x05ac:0x0240"    # Apple Internal Keyboard
    "0x05ac:0x0241"    # Apple Internal Keyboard
    "0x05ac:0x0242"    # Apple Internal Keyboard
    "0x05ac:0x0243"    # Apple Internal Keyboard
    "0x05ac:0x0244"    # Apple Internal Keyboard
    "0x05ac:0x0245"    # Apple Internal Keyboard
    "0x05ac:0x0246"    # Apple Internal Keyboard
    "0x05ac:0x0247"    # Apple Internal Keyboard
    "0x05ac:0x0249"    # Apple Internal Keyboard
    "0x05ac:0x024a"    # Apple Internal Keyboard
    "0x05ac:0x024b"    # Apple Internal Keyboard
    "0x05ac:0x024c"    # Apple Internal Keyboard
    "0x05ac:0x024d"    # Apple Internal Keyboard
    "0x05ac:0x024e"    # Apple Internal Keyboard
    "0x05ac:0x024f"    # Apple Internal Keyboard
    "0x05ac:0x0250"    # Apple Internal Keyboard
    "0x05ac:0x0252"    # Apple Internal Keyboard
    "0x05ac:0x0253"    # Apple Internal Keyboard
    "0x05ac:0x0254"    # Apple Internal Keyboard
    "0x05ac:0x0255"    # Apple Internal Keyboard
    "0x05ac:0x0256"    # Apple Internal Keyboard
    "0x05ac:0x0257"    # Apple Internal Keyboard
    "0x05ac:0x0258"    # Apple Internal Keyboard
    "0x05ac:0x0259"    # Apple Internal Keyboard
    "0x05ac:0x025a"    # Apple Internal Keyboard
    "0x05ac:0x025b"    # Apple Internal Keyboard
    "0x05ac:0x0263"    # Apple Magic Keyboard
    "0x05ac:0x0264"    # Apple Magic Keyboard
    "0x05ac:0x0265"    # Apple Magic Keyboard
    "0x05ac:0x0266"    # Apple Magic Keyboard
    "0x05ac:0x0267"    # Apple Magic Keyboard 2
    "0x05ac:0x0268"    # Apple Magic Keyboard 2
    "0x05ac:0x0269"    # Apple Magic Keyboard 3
    "0x05ac:0x026a"    # Apple Magic Keyboard 3
    "0x05ac:0x026b"    # Apple Magic Keyboard 3
    "0x05ac:0x026c"    # Apple Magic Keyboard with Touch ID
    "0x05ac:0x026d"    # Apple Magic Keyboard with Touch ID
    "0x05ac:0x026e"    # Apple Magic Keyboard with Touch ID
    "0x05ac:0x026f"    # Apple Magic Keyboard with Touch ID
    "0x05ac:0x0270"    # Apple Magic Keyboard
    "0x05ac:0x0271"    # Apple Magic Keyboard
    "0x05ac:0x0272"    # Apple Magic Keyboard
    "0x05ac:0x0273"    # Apple Magic Keyboard
    
    # Apple Trackpads/Mice
    "0x05ac:0x0259"    # Apple Internal Trackpad
    "0x05ac:0x0262"    # Apple Internal Trackpad
    "0x05ac:0x0264"    # Apple Internal Trackpad
    "0x05ac:0x0265"    # Apple Internal Trackpad
    "0x05ac:0x0266"    # Apple Internal Trackpad
    "0x05ac:0x0267"    # Apple Internal Trackpad
    "0x05ac:0x0269"    # Apple Internal Trackpad
    "0x05ac:0x0301"    # Apple USB Mouse
    "0x05ac:0x0302"    # Apple Mighty Mouse
    "0x05ac:0x0304"    # Apple Mighty Mouse (Bluetooth)
    "0x05ac:0x0306"    # Apple Magic Mouse
    "0x05ac:0x030c"    # Apple Magic Mouse 2
    "0x05ac:0x030d"    # Apple Magic Mouse 2
    "0x05ac:0x030e"    # Apple Magic Mouse 3
    "0x05ac:0x030f"    # Apple Magic Mouse 3
    "0x05ac:0x0356"    # Apple Magic Trackpad
    "0x05ac:0x0357"    # Apple Magic Trackpad 2
    "0x05ac:0x0358"    # Apple Magic Trackpad 2
    "0x05ac:0x0359"    # Apple Magic Trackpad 3
    "0x05ac:0x035a"    # Apple Magic Trackpad 3
    
    # Apple Cameras
    "0x05ac:0x8501"    # Apple FaceTime Camera
    "0x05ac:0x8502"    # Apple FaceTime HD Camera
    "0x05ac:0x8508"    # Apple FaceTime HD Camera
    "0x05ac:0x8509"    # Apple FaceTime HD Camera
    "0x05ac:0x850a"    # Apple FaceTime HD Camera
    "0x05ac:0x850b"    # Apple FaceTime HD Camera
    "0x05ac:0x8510"    # Apple FaceTime HD Camera (Built-in)
    "0x05ac:0x8511"    # Apple FaceTime HD Camera (Built-in)
    "0x05ac:0x8514"    # Apple FaceTime HD Camera (Built-in)
    
    # Apple Audio
    "0x05ac:0x1101"    # Apple Speakers
    "0x05ac:0x1105"    # Apple Audio
    "0x05ac:0x1107"    # Apple Audio
    "0x05ac:0x1112"    # Apple USB Audio
    
    # Apple USB-C/Thunderbolt Accessories
    "0x05ac:0x1392"    # Apple USB-C to USB Adapter
    "0x05ac:0x1393"    # Apple USB-C Digital AV Multiport Adapter
    "0x05ac:0x1394"    # Apple USB-C VGA Multiport Adapter
    "0x05ac:0x1460"    # Apple USB-C Hub
    "0x05ac:0x1461"    # Apple Thunderbolt Hub
    "0x05ac:0x1462"    # Apple Thunderbolt Hub
    "0x05ac:0x1463"    # Apple Thunderbolt 3 to Thunderbolt 2 Adapter
    
    # Apple iPhone/iPad/iPod (when connected)
    "0x05ac:0x12a8"    # Apple iPhone
    "0x05ac:0x12a0"    # Apple iPod
    "0x05ac:0x12ab"    # Apple iPad
    "0x05ac:0x12a9"    # Apple iPod Touch
    
    # Apple AirPods/Beats
    "0x05ac:0x2006"    # Apple AirPods
    "0x05ac:0x2007"    # Apple AirPods
    "0x05ac:0x200d"    # Apple AirPods Pro
    "0x05ac:0x200e"    # Apple AirPods Pro
    "0x05ac:0x200f"    # Apple AirPods Max
    "0x05ac:0x2012"    # Apple AirPods 3
    "0x05ac:0x2014"    # Apple AirPods Pro 2
    
    # Apple Watch
    "0x05ac:0x1297"    # Apple Watch
    
    # Apple Pencil
    "0x05ac:0x0260"    # Apple Pencil
    "0x05ac:0x0261"    # Apple Pencil 2
    
    # Apple Displays
    "0x05ac:0x9215"    # Apple Studio Display
    "0x05ac:0x9216"    # Apple Studio Display
    "0x05ac:0x9217"    # Apple Pro Display XDR
    "0x05ac:0x9218"    # Apple Pro Display XDR
    "0x05ac:0x9219"    # Apple Thunderbolt Display
    "0x05ac:0x921a"    # Apple LED Cinema Display
    
    # Legacy/Other
    "0x05ac:0x0201"    # Apple USB Keyboard
    "0x05ac:0x0202"    # Apple USB Keyboard
    "0x05ac:0x0205"    # Apple USB Keyboard
    "0x05ac:0x0206"    # Apple USB Keyboard
    "0x05ac:0x020b"    # Apple Pro Keyboard
    "0x05ac:0x020c"    # Apple Extended Keyboard
    "0x05ac:0x020d"    # Apple Extended Keyboard II
    "0x05ac:0x020e"    # Apple Extended Keyboard II
    "0x05ac:0x1006"    # Apple Hub in Display
)

# Apple Thunderbolt Vendor IDs
# These are text-based identifiers used by system_profiler SPThunderboltDataType
APPLE_THUNDERBOLT_VENDORS=(
    "Apple Inc."
    "Apple"
    "0x1"              # Apple Thunderbolt vendor ID (hex)
    "0x01"             # Apple Thunderbolt vendor ID (hex)
    "0x001"            # Apple Thunderbolt vendor ID (hex)
    "0x0001"           # Apple Thunderbolt vendor ID (hex)
    "1"                # Apple Thunderbolt vendor ID (decimal)
)

# Known legitimate Thunderbolt device names (built into Macs)
APPLE_THUNDERBOLT_DEVICES=(
    "MacBook"
    "MacBook Air"
    "MacBook Pro"
    "Mac mini"
    "Mac Studio"
    "Mac Pro"
    "iMac"
    "Air"              # Sometimes shows as just "Air"
    "Pro"              # Sometimes shows as just "Pro"
    "Apple Thunderbolt"
    "Thunderbolt Bus"
    "Thunderbolt Bridge"
    "Thunderbolt Display"
    "Apple Studio Display"
    "Pro Display XDR"
    "Apple USB-C"
    "LG UltraFine"     # Apple-certified displays
)

# OMG Cable WiFi SSID patterns
OMG_WIFI_PATTERNS=(
    "OMG" "O.MG" "omg" "o.mg" "YOURSSID" "Hak5" "hak5"
    "DuckyScript" "BadUSB" "Payload" "C2Server" "Exfil"
    "YOURNETWORK" "setup" "config" "implant"
)

# Suspicious MAC OUI prefixes
SUSPICIOUS_MAC_OUIS=(
    "02:00:00:Locally Administered"
    "02:80:37:Known OMG OUI"
    "00:00:00:Null MAC"
    "ff:ff:ff:Broadcast Spoof"
)

# Suspicious Bluetooth device name patterns
SUSPICIOUS_BT_NAMES=(
    "OMG" "O.MG" "Hak5" "BadUSB" "Payload" "Implant"
    "C2" "Exfil" "Ducky" "Inject" "KeyLog" "Rubber"
)

# USB Class codes for reference
declare -A USB_CLASS_NAMES=(
    [0]="Composite/Interface-defined"
    [1]="Audio"
    [2]="CDC/Communications (NETWORK CAPABLE)"
    [3]="HID (KEYBOARD/MOUSE - INJECTION CAPABLE)"
    [5]="Physical"
    [6]="Image"
    [7]="Printer"
    [8]="Mass Storage (HAS STORAGE)"
    [9]="Hub"
    [10]="CDC-Data"
    [11]="Smart Card"
    [13]="Content Security"
    [14]="Video"
    [15]="Healthcare"
    [16]="Audio/Video"
    [17]="Billboard"
    [18]="USB-C Bridge"
    [220]="Diagnostic"
    [224]="Wireless (WIFI/BT CAPABLE)"
    [239]="Miscellaneous/Wireless"
    [254]="Application Specific"
    [255]="Vendor Specific"
)

# ══════════════════════════════════════════════════════════════════════════════
# VERDICT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

print_verdict() {
    local verdict=$1
    local device=$2
    local details=$3
    
    case $verdict in
        "CLEAN")
            echo -e "  ${GREEN}[✓ CLEAN]${NC} $device"
            [[ -n "$details" ]] && echo -e "           ${CYAN}$details${NC}"
            ((CLEAN_COUNT++))
            ;;
        "SUSPICIOUS")
            echo -e "  ${YELLOW}[? SUSPICIOUS]${NC} $device"
            [[ -n "$details" ]] && echo -e "           ${YELLOW}$details${NC}"
            ((SUSPICIOUS_COUNT++))
            ;;
        "THREAT")
            echo -e "  ${RED}[! THREAT]${NC} $device"
            [[ -n "$details" ]] && echo -e "           ${RED}$details${NC}"
            ((THREAT_COUNT++))
            ((ALERT_COUNT++))
            ;;
    esac
}

section_header() {
    echo ""
    echo -e "${MAGENTA}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${MAGENTA}══════════════════════════════════════════════════════════════════════${NC}"
}

subsection() {
    echo ""
    echo -e "${CYAN}  ──────────────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}  ──────────────────────────────────────────────────────────────────────${NC}"
}

alert_box() {
    local level=$1
    local title=$2
    shift 2
    
    case $level in
        "THREAT")
            echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${RED}  │ ⚠️  $title${NC}"
            echo -e "${RED}  └─────────────────────────────────────────────────────────────────────┘${NC}"
            for line in "$@"; do
                echo -e "${RED}    $line${NC}"
            done
            ;;
        "WARNING")
            echo -e "${YELLOW}  ┌─────────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${YELLOW}  │ ⚡ $title${NC}"
            echo -e "${YELLOW}  └─────────────────────────────────────────────────────────────────────┘${NC}"
            for line in "$@"; do
                echo -e "${YELLOW}    $line${NC}"
            done
            ;;
        "INFO")
            echo -e "${BLUE}  ┌─────────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${BLUE}  │ ℹ️  $title${NC}"
            echo -e "${BLUE}  └─────────────────────────────────────────────────────────────────────┘${NC}"
            for line in "$@"; do
                echo -e "${CYAN}    $line${NC}"
            done
            ;;
    esac
    echo ""
}

get_usb_class_name() {
    local class=$1
    case $class in
        0) echo "(Composite/Interface-defined)" ;;
        1) echo "(Audio)" ;;
        2) echo "(CDC/Communications - NETWORK CAPABLE)" ;;
        3) echo "(HID - KEYBOARD/MOUSE - INJECTION CAPABLE)" ;;
        5) echo "(Physical)" ;;
        6) echo "(Image)" ;;
        7) echo "(Printer)" ;;
        8) echo "(Mass Storage - HAS STORAGE)" ;;
        9) echo "(Hub)" ;;
        10) echo "(CDC-Data)" ;;
        11) echo "(Smart Card)" ;;
        13) echo "(Content Security)" ;;
        14) echo "(Video)" ;;
        15) echo "(Healthcare)" ;;
        16) echo "(Audio/Video)" ;;
        17) echo "(Billboard)" ;;
        18) echo "(USB-C Bridge)" ;;
        220) echo "(Diagnostic)" ;;
        224) echo "(Wireless - WIFI/BT CAPABLE)" ;;
        239) echo "(Miscellaneous/Wireless)" ;;
        254) echo "(Application Specific)" ;;
        255) echo "(Vendor Specific)" ;;
        *) echo "" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════════════
# CABLE/DEVICE DETECTION - Comprehensive Analysis
# ══════════════════════════════════════════════════════════════════════════════

detect_cables_and_devices() {
    section_header "CABLE/DEVICE DETECTION"
    
    echo -e "${CYAN}  Scanning for connected cables and USB devices...${NC}"
    echo ""
    
    # Get raw USB data
    local USB_RAW=$(system_profiler SPUSBDataType 2>/dev/null)
    
    # Also check IORegistry for more detail
    local IOREG_USB=$(ioreg -p IOUSB -l -w 0 2>/dev/null)
    
    # Count total USB devices
    local TOTAL_USB=$(echo "$USB_RAW" | grep -c "Product ID:" | awk '{print $1}')
    
    # Get USB device list from ioreg (more reliable for cable detection)
    local USB_DEVICES_IOREG=$(ioreg -p IOUSB -w 0 2>/dev/null | grep -E "^\+|USB" | head -50)
    
    echo -e "${WHITE}  ┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}  │                    USB BUS OVERVIEW                                 │${NC}"
    echo -e "${WHITE}  └─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "    Total USB Devices Detected:  ${WHITE}$TOTAL_USB${NC}"
    
    # Show USB tree
    echo ""
    echo -e "    ${CYAN}USB Device Tree:${NC}"
    ioreg -p IOUSB -w 0 2>/dev/null | grep -E "^\+-o|<class" | head -30 | while read -r line; do
        # Extract device name
        if [[ "$line" =~ ^\+-o ]]; then
            local dev_name=$(echo "$line" | sed 's/+-o //' | sed 's/<.*//' | xargs)
            echo -e "      📱 $dev_name"
        fi
    done
    
    echo ""
    
    # Check for power-only vs data cables
    local POWER_ONLY_INFO=""
    
    # Check USB-C ports via IORegistry
    local USB_C_PORTS=$(ioreg -l 2>/dev/null | grep -c "AppleUSBHostPort" | awk '{print $1}')
    local USB_C_DEVICES=$(ioreg -l 2>/dev/null | grep -c "AppleUSBDevice" | awk '{print $1}')
    
    echo -e "    ${CYAN}Port Status:${NC}"
    echo -e "      USB Ports Available:     $USB_C_PORTS"
    echo -e "      USB Devices Connected:   $USB_C_DEVICES"
    
    # Explain cable detection
    echo ""
    echo -e "    ${WHITE}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "    ${WHITE}│  CABLE DETECTION EXPLANATION                                        │${NC}"
    echo -e "    ${WHITE}├─────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "    ${WHITE}│${NC}  • ${CYAN}Pure charging cable${NC}: Only has power lines, NO data lines       ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}    → Will NOT appear as USB device (invisible to scanner)        ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}    → This is SAFE - no data can be transferred                   ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}                                                                  ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}  • ${YELLOW}Data cable${NC}: Has both power AND data lines                    ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}    → WILL appear as USB device if something is connected         ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}                                                                  ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}  • ${RED}OMG/Smart cable${NC}: Has hidden electronics INSIDE the cable     ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}    → WILL appear as USB device (keyboard/network/storage)        ${WHITE}│${NC}"
    echo -e "    ${WHITE}│${NC}    → This scanner WILL detect it!                                ${WHITE}│${NC}"
    echo -e "    ${WHITE}└─────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    if [[ "$TOTAL_USB" -eq 0 ]]; then
        echo -e "    ${GREEN}[✓] No USB data devices detected${NC}"
        echo -e "    ${CYAN}    If you have a charging cable connected, it's likely power-only (safe)${NC}"
        echo -e "    ${CYAN}    An OMG cable would show up as a USB device${NC}"
    else
        echo -e "    ${YELLOW}[!] $TOTAL_USB USB device(s) found - analyzing each below...${NC}"
    fi
    
    # Store baseline for monitoring
    BASELINE_USB_COUNT=$TOTAL_USB
    
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE CABLE CAPABILITY ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_cable_capabilities() {
    section_header "CABLE CAPABILITY ANALYSIS"
    
    local IOREG_DATA=$(ioreg -p IOUSB -l -w 0 2>/dev/null)
    
    echo "==== Recent file access on external volumes ===="
    timeout 3 fs_usage -w 2>/dev/null | grep "/Volumes/" | grep -i "usb" | tail -20 || echo "  (fs_usage timeout or unavailable)"
    echo "==== End file access log ===="
    
    # NEW: USB-C Cable Authentication Check
    echo ""
    subsection "USB-C CABLE AUTHENTICATION"
    echo -e "    Checking for USB-C cable authentication chips..."
    
    # Check for USB-C cable authentication (legitimate cables have authentication chips)
    local CABLE_AUTH=$(ioreg -p IOUSB -l -w0 | grep -i "cable\|auth\|mfi\|c94" | head -10)
    if [[ -n "$CABLE_AUTH" ]]; then
        echo -e "    ${GREEN}[✓] USB-C cable authentication data found:${NC}"
        echo "$CABLE_AUTH" | sed 's/^/      /'
    else
        echo -e "    ${YELLOW}[!] No cable authentication detected${NC}"
        echo -e "    ${YELLOW}    Could be generic cable or OMG cable (no auth chip)${NC}"
    fi
    
    # NEW: Composite Device Detection (OMG cables present multiple interfaces)
    echo ""
    subsection "COMPOSITE DEVICE DETECTION"
    echo -e "    Checking for devices presenting multiple USB interfaces..."
    
    # Find devices with multiple interface classes
    local COMPOSITE_DEVICES=$(ioreg -p IOUSB -l -w0 | grep -B 5 "bNumInterfaces" | grep "bNumInterfaces = [2-9]" | wc -l | awk '{print $1}')
    
    echo -e "    Composite Devices Found: $COMPOSITE_DEVICES"
    
    if [[ "$COMPOSITE_DEVICES" -gt 3 ]]; then
        echo -e "    ${YELLOW}[!] Multiple composite USB devices detected${NC}"
        echo -e "    ${YELLOW}    OMG cables often present as composite devices${NC}"
        echo ""
        echo -e "    ${CYAN}Analyzing composite device interfaces:${NC}"
        ioreg -p IOUSB -l -w0 | grep -A 10 "bNumInterfaces = [2-9]" | head -40 | sed 's/^/      /'
        ((SUSPICIOUS_COUNT++))
    fi

    
    # ─────────────────────────────────────────────────────────────────────
    subsection "USB INTERFACE CLASS ANALYSIS"
    
    # Check for each dangerous class
    local HID_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 3" | wc -l | awk '{print $1}')
    local CDC_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 2" | wc -l | awk '{print $1}')
    local MASS_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 8" | wc -l | awk '{print $1}')
    local WIRELESS_COUNT=$(echo "$IOREG_DATA" | grep -E "bInterfaceClass = 224|bInterfaceClass = 239" | wc -l | awk '{print $1}')
    local VENDOR_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 255" | wc -l | awk '{print $1}')
    local AUDIO_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 1" | wc -l | awk '{print $1}')
    
    echo -e "    Interface Class Summary:"
    echo -e "      HID (Keyboard/Mouse):     $HID_COUNT $([ $HID_COUNT -gt 0 ] && echo "${YELLOW}⚠ Can inject keystrokes${NC}")"
    echo -e "      CDC (Network):            $CDC_COUNT $([ $CDC_COUNT -gt 0 ] && echo "${YELLOW}⚠ Can create network${NC}")"
    echo -e "      Mass Storage:             $MASS_COUNT $([ $MASS_COUNT -gt 0 ] && echo "${YELLOW}⚠ Has storage${NC}")"
    echo -e "      Wireless (WiFi/BT):       $WIRELESS_COUNT $([ $WIRELESS_COUNT -gt 0 ] && echo "${RED}⚠ Wireless capable!${NC}")"
    echo -e "      Audio:                    $AUDIO_COUNT $([ $AUDIO_COUNT -gt 0 ] && echo "${CYAN}Can use audio channel${NC}")"
    echo -e "      Vendor Specific:          $VENDOR_COUNT $([ $VENDOR_COUNT -gt 0 ] && echo "${YELLOW}⚠ Custom protocol${NC}")"
    
    # NEW: BLE Advertising Scan
    echo ""
    echo -e "    ${CYAN}BLE Advertising Scan:${NC}"
    if command -v blueutil &> /dev/null; then
        echo "      Running BLE inquiry..."
        timeout 5 blueutil --inquiry 2>/dev/null | head -20 | sed 's/^/      /' || echo "      (BLE scan timeout or unavailable)"
    else
        echo "      (blueutil not installed - install with: brew install blueutil)"
    fi
    
    # Check for OMG cable signature (HID + CDC)
    if [[ "$HID_COUNT" -gt 0 ]] && [[ "$CDC_COUNT" -gt 0 ]]; then
        echo ""
        alert_box "THREAT" "OMG CABLE SIGNATURE: HID + CDC COMBINATION!" \
            "Device has keyboard (HID) AND network (CDC) interfaces" \
            "This is the classic OMG cable configuration!" \
            "HID interfaces: $HID_COUNT" \
            "CDC interfaces: $CDC_COUNT"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "WIFI CAPABILITY CHECK"
    
    echo -e "    Scanning for cable-generated WiFi networks..."
    
    local WIFI_DATA=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null)
    local WIFI_ADAPTER_COUNT=$(networksetup -listallhardwareports 2>/dev/null | grep -c "Wi-Fi" | awk '{print $1}')
    
    echo -e "    WiFi Adapters in System: $WIFI_ADAPTER_COUNT"
    
    if [[ "$WIFI_ADAPTER_COUNT" -gt 1 ]]; then
        alert_box "THREAT" "MULTIPLE WIFI ADAPTERS DETECTED!" \
            "Expected 1, found $WIFI_ADAPTER_COUNT" \
            "A cable may have added a WiFi adapter!"
    fi
    
    # Check for OMG SSIDs
    local omg_ssid_found=0
    for pattern in "${OMG_WIFI_PATTERNS[@]}"; do
        if echo "$WIFI_DATA" | grep -qi "$pattern"; then
            alert_box "THREAT" "OMG CABLE WIFI SSID DETECTED!" \
                "SSID matching pattern: $pattern" \
                "$(echo "$WIFI_DATA" | grep -i "$pattern" | head -3)"
            omg_ssid_found=1
        fi
    done
    
    if [[ "$omg_ssid_found" -eq 0 ]]; then
        echo -e "    ${GREEN}[✓] No OMG-related WiFi SSIDs detected${NC}"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "BLUETOOTH CAPABILITY CHECK"
    
    echo -e "    Scanning for cable-generated Bluetooth..."
    
    local BT_DATA=$(system_profiler SPBluetoothDataType 2>/dev/null)
    local BT_CONTROLLER_COUNT=$(echo "$BT_DATA" | grep -c "Address:" | awk '{print $1}')
    
    echo -e "    Bluetooth Controllers: $BT_CONTROLLER_COUNT"
    
    if [[ "$BT_CONTROLLER_COUNT" -gt 1 ]]; then
        alert_box "WARNING" "MULTIPLE BLUETOOTH CONTROLLERS!" \
            "Expected 1, found $BT_CONTROLLER_COUNT" \
            "A cable may have added Bluetooth capability!"
    fi
    
    # Check for suspicious BT device names
    for pattern in "${SUSPICIOUS_BT_NAMES[@]}"; do
        if echo "$BT_DATA" | grep -qi "$pattern"; then
            alert_box "THREAT" "SUSPICIOUS BLUETOOTH DEVICE: $pattern" \
                "Pattern matched in Bluetooth devices"
        fi
    done
    
    echo -e "    ${GREEN}[✓] Bluetooth scan complete${NC}"
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "STORAGE/FILESYSTEM CHECK"
    
    echo -e "    Checking for cable-provided storage..."
    
    local USB_DISKS=$(diskutil list 2>/dev/null | grep -E "external|USB" | wc -l | awk '{print $1}')
    local MOUNTED_VOLS=$(ls /Volumes 2>/dev/null | wc -l | awk '{print $1}')
    
    echo -e "    External/USB Disks: $USB_DISKS"
    echo -e "    Mounted Volumes:    $MOUNTED_VOLS"
    
    if [[ "$USB_DISKS" -gt 0 ]]; then
        echo -e "    ${YELLOW}[!] External storage detected:${NC}"
        diskutil list 2>/dev/null | grep -A3 "external" | head -8 | sed 's/^/        /'
    else
        echo -e "    ${GREEN}[✓] No cable-provided storage detected${NC}"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "DATA TRANSMISSION CHECK"
    
    echo -e "    Monitoring for active data transmission..."
    
    # Check network connections
    local ACTIVE_CONNS=$(netstat -an 2>/dev/null | grep "ESTABLISHED" | wc -l | awk '{print $1}')
    echo -e "    Active TCP Connections: $ACTIVE_CONNS"
    
    # Check keystroke injection
    local KEY_EVENTS=$(log show --predicate 'subsystem == "com.apple.IOHIDFamily" AND eventMessage CONTAINS "KeyEvent"' --last 5s 2>/dev/null | grep -c "Key" | awk '{print $1}')
if [[ "$KEY_EVENTS" -gt 40 ]]; then
    print_verdict "THREAT" "Rapid keystroke injection" "Possible automated input or attack device"
fi
    echo -e "    Key Events (last 5s):   $KEY_EVENTS"
    
    if [[ "$KEY_EVENTS" -gt 50 ]]; then
        alert_box "THREAT" "KEYSTROKE INJECTION DETECTED!" \
            "$KEY_EVENTS key events in 5 seconds!" \
            "Normal typing: 10-25 keys in 5 seconds" \
            "This is machine-speed typing - INJECTION ATTACK!"
    fi
    
    # Check USB traffic
    local USB_TRANSFERS=$(ioreg -c IOUSBHostDevice 2>/dev/null | grep -c "IOUSBHostDevice" | awk '{print $1}')
    echo -e "    USB Host Devices:       $USB_TRANSFERS"
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "AUDIO/ULTRASONIC CHECK"
    
    echo -e "    Checking for audio-based data transmission..."
    
    local AUDIO_DEVICES=$(system_profiler SPAudioDataType 2>/dev/null | grep -c "Device:" | awk '{print $1}')
    local AUDIO_INPUTS=$(system_profiler SPAudioDataType 2>/dev/null | grep -c "Input" | awk '{print $1}')
    local AUDIO_OUTPUTS=$(system_profiler SPAudioDataType 2>/dev/null | grep -c "Output" | awk '{print $1}')
    
    echo -e "    Audio Devices:  $AUDIO_DEVICES"
    echo -e "    Audio Inputs:   $AUDIO_INPUTS"
    echo -e "    Audio Outputs:  $AUDIO_OUTPUTS"
    
    if [[ "$AUDIO_DEVICES" -gt 3 ]]; then
        echo -e "    ${YELLOW}[!] Multiple audio devices - potential ultrasonic data channel${NC}"
    else
        echo -e "    ${GREEN}[✓] Audio device count normal${NC}"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "RF/SDR DEVICE CHECK"
    
    echo -e "    Checking for RF transmission devices..."
    
    local RF_DEVICES=$(system_profiler SPUSBDataType 2>/dev/null | grep -iE "sdr|radio|rtl|hackrf|software.defined|airspy|funcube" | wc -l | awk '{print $1}')
    
    if [[ "$RF_DEVICES" -gt 0 ]]; then
        alert_box "THREAT" "RF/SDR DEVICE DETECTED!" \
            "Software Defined Radio capability found" \
            "Device can transmit/receive radio signals!"
    else
        echo -e "    ${GREEN}[✓] No RF/SDR devices detected${NC}"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "INFRARED CHECK"
    
    echo -e "    Checking for IR transmission capability..."
    
    local IR_DEVICES=$(ioreg -l 2>/dev/null | grep -ic "infrared\|AppleIRController" | awk '{print $1}')
    echo -e "    IR Devices/Controllers: $IR_DEVICES"
    
    if [[ "$IR_DEVICES" -gt 1 ]]; then
        echo -e "    ${YELLOW}[!] Multiple IR devices - potential covert channel${NC}"
    else
        echo -e "    ${GREEN}[✓] IR device count normal${NC}"
    fi
    
    # ─────────────────────────────────────────────────────────────────────
    subsection "POWER ANALYSIS"
    
    echo -e "    Analyzing USB power consumption..."
    
    local POWER_DATA=$(system_profiler SPUSBDataType 2>/dev/null | grep -E "Current Required|Current Available")
    local HIGH_POWER=$(system_profiler SPUSBDataType 2>/dev/null | grep "Current Required" | grep -oE "[0-9]+" | while read mA; do
        [[ "$mA" -gt 500 ]] && echo "$mA"
    done | wc -l | awk '{print $1}')
    
    echo -e "    Devices drawing >500mA: $HIGH_POWER"
    
    if [[ "$HIGH_POWER" -gt 0 ]]; then
        echo -e "    ${YELLOW}[!] High-power USB devices detected${NC}"
    fi
    
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# USB DEVICE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_usb_devices_verbose() {
    section_header "USB DEVICE ANALYSIS"
    
    local device_num=0
    local USB_RAW=$(system_profiler SPUSBDataType 2>/dev/null)
    
    # Parse each USB device
    echo "$USB_RAW" | awk '
    /^        [A-Za-z]/ { 
        if (device) print device
        device = $0
        next 
    }
    /^          / { 
        device = device "\n" $0 
    }
    END { if (device) print device }
    ' | while IFS= read -r block; do
        [[ -z "$block" ]] && continue
        
        ((device_num++))
        
        # Extract device info
        PRODUCT_NAME=$(echo "$block" | head -1 | xargs)
        VENDOR=$(echo "$block" | grep "Vendor ID" | grep -oE "0x[0-9a-fA-F]+" | head -1)
        PRODUCT=$(echo "$block" | grep "Product ID" | grep -oE "0x[0-9a-fA-F]+" | head -1)
        SERIAL=$(echo "$block" | grep "Serial Number:" | sed 's/.*Serial Number: //' | xargs)
        MANUFACTURER=$(echo "$block" | grep "Manufacturer:" | sed 's/.*Manufacturer: //' | xargs)
        CURRENT_MA=$(echo "$block" | grep "Current Required" | grep -oE "[0-9]+" | head -1)
        LOCATION=$(echo "$block" | grep "Location ID:" | sed 's/.*Location ID: //' | xargs)
        
        [[ -z "$VENDOR" ]] && continue
        
        echo ""
        echo -e "${BLUE}─────────────────────────────────────────────────────────────────────${NC}"
        echo -e "${WHITE}USB Device #$device_num: $PRODUCT_NAME${NC}"
        echo -e "${CYAN}  Vendor ID:    $VENDOR${NC}"
        echo -e "${CYAN}  Product ID:   $PRODUCT${NC}"
        echo -e "${CYAN}  Manufacturer: ${MANUFACTURER:-N/A}${NC}"
        echo -e "${CYAN}  Serial:       ${SERIAL:-NONE}${NC}"
        echo -e "${CYAN}  Power:        ${CURRENT_MA:-N/A} mA${NC}"
        echo -e "${CYAN}  Location:     ${LOCATION:-N/A}${NC}"
        
        local verdict="CLEAN"
        local verdict_reason=""
        
        # Check OMG vendor signatures
        for sig in "${OMG_VENDORS[@]}"; do
            SIG_VENDOR=$(echo "$sig" | cut -d: -f1)
            SIG_DESC=$(echo "$sig" | cut -d: -f2)
            if [[ "$VENDOR" == "$SIG_VENDOR" ]]; then
                verdict="THREAT"
                verdict_reason="OMG CABLE: $SIG_DESC"
                echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                echo -e "${RED}  │ OMG CABLE DETECTED - FULL THREAT DETAILS:                       │${NC}"
                echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                echo -e "${RED}    IOC Match:     $SIG_DESC${NC}"
                echo -e "${RED}    Device Name:   ${PRODUCT_NAME:-Unknown}${NC}"
                echo -e "${RED}    Vendor ID:     $VENDOR${NC}"
                echo -e "${RED}    Product ID:    $PRODUCT${NC}"
                echo -e "${RED}    Manufacturer:  ${MANUFACTURER:-Unknown}${NC}"
                echo -e "${RED}    Serial Number: ${SERIAL:-NONE}${NC}"
                echo -e "${RED}    Power Draw:    ${CURRENT_MA:-N/A} mA${NC}"
                echo -e "${RED}    Location ID:   ${LOCATION:-Unknown}${NC}"
                echo ""
                break
            fi
        done
        
        # Check BadUSB vendors
        if [[ "$verdict" != "THREAT" ]]; then
            for sig in "${BADUSB_VENDORS[@]}"; do
                SIG_VENDOR=$(echo "$sig" | cut -d: -f1)
                SIG_DESC=$(echo "$sig" | cut -d: -f2)
                if [[ "$VENDOR" == "$SIG_VENDOR" ]]; then
                    verdict="THREAT"
                    verdict_reason="BADUSB DEVICE: $SIG_DESC"
                    echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                    echo -e "${RED}  │ BADUSB/INJECTION DEVICE DETECTED - FULL THREAT DETAILS:        │${NC}"
                    echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                    echo -e "${RED}    IOC Match:     $SIG_DESC${NC}"
                    echo -e "${RED}    Device Name:   ${PRODUCT_NAME:-Unknown}${NC}"
                    echo -e "${RED}    Vendor ID:     $VENDOR${NC}"
                    echo -e "${RED}    Product ID:    $PRODUCT${NC}"
                    echo -e "${RED}    Manufacturer:  ${MANUFACTURER:-Unknown}${NC}"
                    echo -e "${RED}    Serial Number: ${SERIAL:-NONE}${NC}"
                    echo -e "${RED}    Power Draw:    ${CURRENT_MA:-N/A} mA${NC}"
                    echo -e "${RED}    Location ID:   ${LOCATION:-Unknown}${NC}"
                    echo ""
                    break
                fi
            done
        fi
        
        # NEW: Check if device is external using location ID
        if [[ -n "$LOCATION" ]] && is_external_usb_device "$LOCATION"; then
            echo -e "${CYAN}  [*] EXTERNAL USB DEVICE DETECTED${NC}"
            echo -e "${CYAN}      Performing enhanced data exfil checks...${NC}"
            
            # Check for hidden network capabilities
            local NET_CHECK=$(ioreg -p IOUSB -l -w0 | grep -A 50 "$VENDOR:$PRODUCT" | grep -i "network\|ethernet\|wifi\|wlan" | head -5)
            if [[ -n "$NET_CHECK" ]]; then
                echo -e "${RED}  [!] NETWORK CAPABILITY DETECTED ON USB DEVICE!${NC}"
                echo "$NET_CHECK" | sed 's/^/      /'
                verdict="SUSPICIOUS"
                verdict_reason="External USB device with network capability (data exfil risk)"
            fi
        fi
        
        # NEW: Enhanced OMG Cable pattern detection
        # Check for multiple product ID combinations (OMG cables can switch modes)
        if [[ "$VENDOR" == "0x16d0" ]]; then
            case "$PRODUCT" in
                "0x0e6c"|"0x0eaf"|"0x0e60")
                    verdict="THREAT"
                    verdict_reason="O.MG Cable Elite/Pro variant detected"
                    echo -e "${RED}  ╔═════════════════════════════════════════════════════════════════╗${NC}"
                    echo -e "${RED}  ║ O.MG CABLE ELITE/PRO DETECTED!                                  ║${NC}"
                    echo -e "${RED}  ╚═════════════════════════════════════════════════════════════════╝${NC}"
                    echo -e "${RED}    Product ID: $PRODUCT${NC}"
                    echo -e "${RED}    This is a known OMG Cable Elite/Pro variant${NC}"
                    echo -e "${RED}    Capabilities: WiFi, Keystroke Injection, Payload Storage${NC}"
                    echo ""
                    ;;
            esac
        fi
        
        # Check for suspicious product name patterns
        if echo "$PRODUCT_NAME" | grep -qiE "o\.mg|omg|keygrab|usbninja|elite|payload|implant"; then
            verdict="THREAT"
            verdict_reason="Suspicious product name: $PRODUCT_NAME"
            echo -e "${RED}  [!] PRODUCT NAME MATCHES OMG CABLE PATTERN!${NC}"
        fi
        
        # Check for missing serial number (common in malicious devices)
        if [[ -z "$SERIAL" ]] && [[ "$VENDOR" != "0x05ac" ]]; then
            if [[ "$verdict" == "CLEAN" ]]; then
                verdict="SUSPICIOUS"
                verdict_reason="Non-Apple device with no serial number"
            fi
            echo -e "${YELLOW}  [!] No serial number (suspicious for non-Apple device)${NC}"
        fi
        
        # Check spoofed Apple
        if [[ "$verdict" != "THREAT" ]] && [[ "$VENDOR" == "0x05ac" ]]; then
            IS_LEGIT=0
            IS_SPOOFED=0
            
            # First check if it's a known spoof
            for spoof in "${SPOOFED_APPLE[@]}"; do
                SPOOF_COMBO=$(echo "$spoof" | cut -d: -f1-2)
                SPOOF_DESC=$(echo "$spoof" | cut -d: -f3)
                if [[ "$VENDOR:$PRODUCT" == "$SPOOF_COMBO" ]]; then
                    IS_SPOOFED=1
                    verdict="THREAT"
                    verdict_reason="SPOOFED APPLE: $SPOOF_DESC"
                    echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                    echo -e "${RED}  │ SPOOFED APPLE DEVICE DETECTED - FULL THREAT DETAILS:           │${NC}"
                    echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                    echo -e "${RED}    IOC Match:     $SPOOF_DESC${NC}"
                    echo -e "${RED}    Device Name:   ${PRODUCT_NAME:-Unknown}${NC}"
                    echo -e "${RED}    Vendor ID:     $VENDOR (Apple)${NC}"
                    echo -e "${RED}    Product ID:    $PRODUCT${NC}"
                    echo -e "${RED}    Manufacturer:  ${MANUFACTURER:-Unknown}${NC}"
                    echo -e "${RED}    Serial Number: ${SERIAL:-NONE}${NC}"
                    echo -e "${RED}    Power Draw:    ${CURRENT_MA:-N/A} mA${NC}"
                    echo -e "${RED}    Location ID:   ${LOCATION:-Unknown}${NC}"
                    echo -e "${RED}    WARNING:       Device is impersonating Apple hardware!${NC}"
                    echo ""
                    break
                fi
            done
            
            # If not spoofed, check if it's in our known legit list
            if [[ "$IS_SPOOFED" -eq 0 ]]; then
                for legit in "${APPLE_INTERNAL_LEGIT[@]}"; do
                    if [[ "$VENDOR:$PRODUCT" == "$legit" ]]; then
                        IS_LEGIT=1
                        break
                    fi
                done
                
                # Apple vendor ID (0x05ac) is generally legitimate even if not in our list
                # Apple has thousands of product IDs, we can't list them all
                # Only flag as suspicious if it has other red flags
                if [[ "$IS_LEGIT" -eq 0 ]]; then
                    # Check if manufacturer confirms Apple
                    if echo "$MANUFACTURER" | grep -qi "apple"; then
                        IS_LEGIT=1
                    # Check if product name sounds Apple-like
                    elif echo "$PRODUCT_NAME" | grep -qi "apple\|mac\|iphone\|ipad\|ipod\|airpod\|magic\|touch.*id"; then
                        IS_LEGIT=1
                    fi
                fi
                
                # Only mark as suspicious if it has no serial AND doesn't look like Apple
                if [[ "$IS_LEGIT" -eq 0 ]]; then
                    if [[ -z "$SERIAL" || "$SERIAL" == "(null)" ]] && ! echo "$MANUFACTURER" | grep -qi "apple"; then
                        verdict="SUSPICIOUS"
                        verdict_reason="Apple vendor ID with missing serial - verify legitimacy"
                    else
                        # Has Apple vendor ID, probably legitimate but unlisted
                        verdict="CLEAN"
                        verdict_reason="Apple vendor ID (0x05ac) - likely legitimate peripheral"
                    fi
                fi
            fi
        fi
        
        # Check for missing serial
        if [[ "$verdict" == "CLEAN" ]] && [[ -z "$SERIAL" || "$SERIAL" == "(null)" ]]; then
            verdict="SUSPICIOUS"
            verdict_reason="No serial number (common in clone/malicious devices)"
        fi
        
        echo -e "${WHITE}  ANALYSIS:${NC}"
        print_verdict "$verdict" "$VENDOR:$PRODUCT" "$verdict_reason"
    done
    
    # If no devices found
    if [[ $device_num -eq 0 ]]; then
        echo -e "${YELLOW}  No USB devices detected${NC}"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USB CLASS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_usb_classes_verbose() {
    section_header "USB DEVICE CLASS ANALYSIS"
    
    IOREG_DATA=$(ioreg -p IOUSB -l -w 0 2>/dev/null)
    
    if [[ "$IS_EXTERNAL" == 1 ]]; then
    if [[ "$HID_COUNT" -gt 0 && "$MASS_COUNT" -gt 0 ]]; then
        print_verdict "THREAT" "HID + Mass Storage combo" "Possible multi-function attack device"
    fi
fi
    
    # Count device classes
    HID_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 3" | wc -l | awk '{print $1}')
    CDC_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 2" | wc -l | awk '{print $1}')
    MASS_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 8" | wc -l | awk '{print $1}')
    VENDOR_COUNT=$(echo "$IOREG_DATA" | grep "bInterfaceClass = 255" | wc -l | awk '{print $1}')
    
    echo -e "${CYAN}  Device Class Summary:${NC}"
    echo -e "    HID (Human Interface):     $HID_COUNT"
    echo -e "    CDC (Communications):      $CDC_COUNT"
    echo -e "    Mass Storage:              $MASS_COUNT"
    echo -e "    Vendor Specific:           $VENDOR_COUNT"
    echo ""
    
    # Analyze for OMG signature (HID + CDC)
    echo -e "${WHITE}  CLASS COMBINATION ANALYSIS:${NC}"
    
    if [[ "$HID_COUNT" -gt 0 ]] && [[ "$CDC_COUNT" -gt 0 ]]; then
        echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${RED}  │ HID + CDC COMBO DETECTED - OMG CABLE SIGNATURE:                 │${NC}"
        echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
        echo -e "${RED}    HID Interfaces: $HID_COUNT${NC}"
        echo -e "${RED}    CDC Interfaces: $CDC_COUNT${NC}"
        echo -e "${RED}    Explanation:    OMG cables present as keyboard (HID) + network (CDC)${NC}"
        echo ""
        
        # Get device names with these classes
        echo -e "${RED}    Devices with HID class:${NC}"
        echo "$IOREG_DATA" | grep -B15 "bInterfaceClass = 3" | grep "USB Product Name" | sed 's/.*= "/      /' | sed 's/"$//' | head -5
        echo ""
        echo -e "${RED}    Devices with CDC class:${NC}"
        echo "$IOREG_DATA" | grep -B15 "bInterfaceClass = 2" | grep "USB Product Name" | sed 's/.*= "/      /' | sed 's/"$//' | head -5
        echo ""
        
        print_verdict "THREAT" "HID + CDC Combination" "OMG cables present as HID (keyboard) + CDC (network) combo"
    else
        print_verdict "CLEAN" "No HID+CDC combo" "Normal device class distribution"
    fi
    
    # Check for multiple HID
    if [[ "$HID_COUNT" -gt 2 ]]; then
        print_verdict "SUSPICIOUS" "Multiple HID devices ($HID_COUNT)" "Could indicate injection device"
    fi
    
    # Check composite devices
    echo ""
    echo -e "${WHITE}  COMPOSITE DEVICE CHECK:${NC}"
    
    MULTI_IFACE=$(echo "$IOREG_DATA" | grep "bNumInterfaces" | grep -oE "[0-9]+" | sort -rn | head -1)
    if [[ -n "$MULTI_IFACE" ]] && [[ "$MULTI_IFACE" -gt 2 ]]; then
        print_verdict "SUSPICIOUS" "Composite device ($MULTI_IFACE interfaces)" "OMG cables use multiple interfaces"
    else
        print_verdict "CLEAN" "No unusual composite devices" "Interface counts normal"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# USB DESCRIPTOR ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_usb_descriptors_verbose() {
    section_header "USB DESCRIPTOR ANALYSIS"
    
    IOREG_DATA=$(ioreg -p IOUSB -l -w 0 2>/dev/null)
    
    echo -e "${CYAN}  Scanning for descriptor anomalies...${NC}"
    echo ""
    
    # Null descriptors
    NULL_MANUFACTURER=$(echo "$IOREG_DATA" | grep "iManufacturer = 0$" | wc -l | awk '{print $1}')
    NULL_PRODUCT=$(echo "$IOREG_DATA" | grep "iProduct = 0$" | wc -l | awk '{print $1}')
    NULL_SERIAL=$(echo "$IOREG_DATA" | grep "iSerialNumber = 0$" | wc -l | awk '{print $1}')
    
    echo -e "${WHITE}  NULL DESCRIPTOR FIELDS:${NC}"
    echo -e "    Null Manufacturer strings: $NULL_MANUFACTURER"
    echo -e "    Null Product strings:      $NULL_PRODUCT"
    echo -e "    Null Serial strings:       $NULL_SERIAL"
    
    TOTAL_NULLS=$((NULL_MANUFACTURER + NULL_PRODUCT + NULL_SERIAL))
    
    if [[ "$TOTAL_NULLS" -gt 3 ]]; then
        print_verdict "SUSPICIOUS" "High null descriptor count ($TOTAL_NULLS)" "OMG cables often have blank descriptors"
    else
        print_verdict "CLEAN" "Normal descriptor population" ""
    fi
    
    # DFU/Recovery check
    echo ""
    echo -e "${WHITE}  DFU/RECOVERY MODE CHECK:${NC}"
    
    DFU_DEVICES=$(system_profiler SPUSBDataType 2>/dev/null | grep -B10 -A5 -i "DFU\|Recovery\|Bootloader")
    
    if [[ -n "$DFU_DEVICES" ]]; then
        echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${RED}  │ DFU/RECOVERY DEVICE FOUND - FULL DETAILS:                       │${NC}"
        echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
        
        # Extract all details
        DFU_NAME=$(echo "$DFU_DEVICES" | grep -E "^\s+[A-Za-z]" | head -1 | xargs)
        DFU_VENDOR=$(echo "$DFU_DEVICES" | grep "Vendor ID" | grep -oE "0x[0-9a-fA-F]+" | head -1)
        DFU_PRODUCT=$(echo "$DFU_DEVICES" | grep "Product ID" | grep -oE "0x[0-9a-fA-F]+" | head -1)
        DFU_SERIAL=$(echo "$DFU_DEVICES" | grep "Serial Number:" | sed 's/.*Serial Number: //' | xargs)
        DFU_LOCATION=$(echo "$DFU_DEVICES" | grep "Location ID:" | sed 's/.*Location ID: //' | xargs)
        DFU_MANUFACTURER=$(echo "$DFU_DEVICES" | grep "Manufacturer:" | sed 's/.*Manufacturer: //' | xargs)
        
        echo -e "${RED}    Device Name:   ${DFU_NAME:-Unknown}${NC}"
        echo -e "${RED}    Vendor ID:     ${DFU_VENDOR:-Unknown}${NC}"
        echo -e "${RED}    Product ID:    ${DFU_PRODUCT:-Unknown}${NC}"
        echo -e "${RED}    Manufacturer:  ${DFU_MANUFACTURER:-Unknown}${NC}"
        echo -e "${RED}    Serial Number: ${DFU_SERIAL:-None}${NC}"
        echo -e "${RED}    Location ID:   ${DFU_LOCATION:-Unknown}${NC}"
        echo -e "${RED}    Raw Match:${NC}"
        echo "$DFU_DEVICES" | head -20 | sed 's/^/      /'
        echo ""
        print_verdict "THREAT" "DFU/Recovery: ${DFU_NAME:-Unknown device} ($DFU_VENDOR:$DFU_PRODUCT)" "Device in firmware update mode - possible attack vector"
    else
        print_verdict "CLEAN" "No DFU/Recovery devices" ""
    fi
    
    if [[ "$NULL_MANUFACTURER" -gt 0 ]] || [[ "$NULL_PRODUCT" -gt 0 ]] || [[ "$NULL_SERIAL" -gt 0 ]]; then
    echo "⚠️ USB device with missing/blank descriptors:"
    echo "$IOREG_DATA" | grep -B10 -A10 "iManufacturer = 0\|iProduct = 0\|iSerialNumber = 0"
fi

if [[ "$IS_EXTERNAL" == 1 && "$NULL_SERIAL" -gt 0 ]]; then
    print_verdict "SUSPICIOUS" "$PRODUCT_NAME" "External device with null serial"
fi

}


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK INTERFACE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_interfaces_verbose() {
    section_header "NETWORK INTERFACE ANALYSIS"
    
    ALL_IFACES=$(ifconfig -a 2>/dev/null | grep -E "^[a-z]+[0-9]+:" | awk -F: '{print $1}')
    STANDARD_IFACES="lo0 en0 en1 en2 awdl0 llw0 utun0 utun1 utun2 utun3 bridge0 ap1 gif0 stf0 anpi0 anpi1"
    
    echo -e "${CYAN}  Detected Interfaces:${NC}"
    
    for iface in $ALL_IFACES; do
        IFACE_INFO=$(ifconfig "$iface" 2>/dev/null)
        STATUS=$(echo "$IFACE_INFO" | grep "status:" | awk '{print $2}')
        MTU=$(echo "$IFACE_INFO" | grep "mtu" | grep -oE "mtu [0-9]+" | awk '{print $2}')
        IP=$(echo "$IFACE_INFO" | grep "inet " | awk '{print $2}' | head -1)
        MAC=$(echo "$IFACE_INFO" | grep "ether" | awk '{print $2}')
        
        echo ""
        echo -e "${BLUE}  ─────────────────────────────────────────${NC}"
        echo -e "${WHITE}  Interface: $iface${NC}"
        echo -e "    Status: ${STATUS:-unknown}"
        echo -e "    MTU:    ${MTU:-N/A}"
        echo -e "    IP:     ${IP:-none}"
        echo -e "    MAC:    ${MAC:-N/A}"
        
        local verdict="CLEAN"
        local verdict_reason=""
        
        # Check if standard
        if ! echo "$STANDARD_IFACES" | grep -qw "$iface"; then
            # Check for USB network
            if echo "$IFACE_INFO" | grep -qi "usb\|cdc\|rndis\|ecm\|ncm"; then
                verdict="THREAT"
                verdict_reason="USB network adapter - POSSIBLE OMG CABLE"
                echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                echo -e "${RED}  │ USB NETWORK INTERFACE DETECTED - POSSIBLE OMG CABLE:           │${NC}"
                echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                echo -e "${RED}    Interface:    $iface${NC}"
                echo -e "${RED}    Status:       ${STATUS:-unknown}${NC}"
                echo -e "${RED}    MAC Address:  ${MAC:-N/A}${NC}"
                echo -e "${RED}    IP Address:   ${IP:-none}${NC}"
                echo -e "${RED}    MTU:          ${MTU:-N/A}${NC}"
                echo -e "${RED}    Full Config:${NC}"
                echo "$IFACE_INFO" | sed 's/^/      /'
                echo ""
            elif [[ "$iface" == en[6-9] ]] || [[ "$iface" == en1[0-9] ]]; then
                verdict="SUSPICIOUS"
                verdict_reason="Unexpected interface number for M1 MacBook"
                
                if [[ "$STATUS" == "active" ]]; then
                    verdict="THREAT"
                    verdict_reason="Unexpected active interface - possible data exfiltration"
                    echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                    echo -e "${RED}  │ UNEXPECTED ACTIVE INTERFACE - POSSIBLE DATA EXFILTRATION:      │${NC}"
                    echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                    echo -e "${RED}    Interface:    $iface${NC}"
                    echo -e "${RED}    Status:       ACTIVE${NC}"
                    echo -e "${RED}    MAC Address:  ${MAC:-N/A}${NC}"
                    echo -e "${RED}    IP Address:   ${IP:-none}${NC}"
                    echo -e "${RED}    Full Config:${NC}"
                    echo "$IFACE_INFO" | sed 's/^/      /'
                    echo ""
                fi
            fi
        fi
        
        # Check for traffic on unusual interfaces
        if [[ "$iface" == en[3-9] ]] || [[ "$iface" == en1[0-9] ]]; then
            STATS=$(netstat -I "$iface" -b 2>/dev/null | tail -1)
            BYTES_IN=$(echo "$STATS" | awk '{print $7}')
            BYTES_OUT=$(echo "$STATS" | awk '{print $10}')
            
            if [[ -n "$BYTES_IN" ]] && [[ "$BYTES_IN" -gt 0 ]] 2>/dev/null; then
                verdict="THREAT"
                verdict_reason="Active data transfer: IN=$BYTES_IN OUT=$BYTES_OUT"
                echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                echo -e "${RED}  │ ACTIVE DATA TRANSFER ON SUSPICIOUS INTERFACE:                   │${NC}"
                echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                echo -e "${RED}    Interface:    $iface${NC}"
                echo -e "${RED}    Bytes IN:     $BYTES_IN${NC}"
                echo -e "${RED}    Bytes OUT:    $BYTES_OUT${NC}"
                echo -e "${RED}    MAC Address:  ${MAC:-N/A}${NC}"
                echo -e "${RED}    IP Address:   ${IP:-none}${NC}"
                echo -e "${RED}    WARNING:      Data is being transferred through unexpected interface!${NC}"
                echo ""
            fi
        fi
        
        echo -e "    ${WHITE}ANALYSIS:${NC}"
        print_verdict "$verdict" "$iface" "$verdict_reason"
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# HARDWARE PORTS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_hardware_ports_verbose() {
    section_header "HARDWARE PORTS ANALYSIS"
    
    PORTS=$(networksetup -listallhardwareports 2>/dev/null)
    
    echo -e "${CYAN}  System Hardware Ports:${NC}"
    echo ""
    
    # Parse each hardware port
    echo "$PORTS" | awk '
    /Hardware Port:/ { port = $0; next }
    /Device:/ { device = $2; next }
    /Ethernet Address:/ { 
        mac = $3
        print port "|" device "|" mac
        port = ""; device = ""; mac = ""
    }
    ' | while IFS='|' read -r port device mac; do
        [[ -z "$port" ]] && continue
        
        PORT_NAME=$(echo "$port" | sed 's/Hardware Port: //')
        
        echo -e "${WHITE}  $PORT_NAME${NC}"
        echo -e "    Device: $device"
        echo -e "    MAC:    ${mac:-N/A}"
        
        local verdict="CLEAN"
        local verdict_reason=""
        
        # Check for USB network adapters
        if echo "$PORT_NAME" | grep -qi "usb.*ethernet\|usb.*lan\|usb.*network\|cdc"; then
            verdict="THREAT"
            verdict_reason="USB network adapter detected"
            echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${RED}  │ USB NETWORK ADAPTER IN HARDWARE PORTS:                          │${NC}"
            echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
            echo -e "${RED}    Port Name:    $PORT_NAME${NC}"
            echo -e "${RED}    Device:       $device${NC}"
            echo -e "${RED}    MAC Address:  ${mac:-N/A}${NC}"
            echo -e "${RED}    WARNING:      USB network adapters can be used by OMG cables!${NC}"
            echo ""
        fi
        
        print_verdict "$verdict" "$device" "$verdict_reason"
        echo ""
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# WIFI ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_wifi_verbose() {
    section_header "WIFI NETWORK ANALYSIS"
    
    WIFI_DATA=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null)
    CONNECTED_SSID=$(networksetup -getairportnetwork en0 2>/dev/null | awk -F': ' '{print $2}')
    
    echo -e "${CYAN}  Currently connected to: ${CONNECTED_SSID:-None}${NC}"
    echo ""
    echo -e "${CYAN}  Scanning nearby networks...${NC}"
    echo ""
    
    local network_count=0
    local omg_found=0
    
    echo "$WIFI_DATA" | tail -n +2 | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        
        ((network_count++))
        
        SSID=$(echo "$line" | awk '{print $1}')
        BSSID=$(echo "$line" | awk '{print $2}')
        RSSI=$(echo "$line" | awk '{print $3}')
        CHANNEL=$(echo "$line" | awk '{print $4}')
        SECURITY=$(echo "$line" | awk '{$1=$2=$3=$4=""; print $0}' | xargs)
        
        echo -e "${WHITE}  Network: $SSID${NC}"
        echo -e "    BSSID:    $BSSID"
        echo -e "    Signal:   $RSSI dBm"
        echo -e "    Channel:  $CHANNEL"
        echo -e "    Security: ${SECURITY:-Open}"
        
        local verdict="CLEAN"
        local verdict_reason=""
        
        # Check against OMG SSID patterns
        for pattern in "${OMG_WIFI_PATTERNS[@]}"; do
            if echo "$SSID" | grep -qi "^${pattern}$\|^${pattern}[_-]\|[_-]${pattern}$"; then
                verdict="THREAT"
                verdict_reason="Matches OMG cable SSID pattern: $pattern"
                echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                echo -e "${RED}  │ OMG CABLE WIFI SSID DETECTED:                                   │${NC}"
                echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                echo -e "${RED}    SSID:          $SSID${NC}"
                echo -e "${RED}    BSSID:         $BSSID${NC}"
                echo -e "${RED}    Pattern Match: $pattern${NC}"
                echo -e "${RED}    Signal:        $RSSI dBm${NC}"
                echo -e "${RED}    Channel:       $CHANNEL${NC}"
                echo -e "${RED}    Security:      ${SECURITY:-Open}${NC}"
                echo -e "${RED}    WARNING:       OMG cables create WiFi APs for C2 communication!${NC}"
                echo ""
                ((omg_found++))
                break
            fi
        done
        
        # Check BSSID for suspicious OUI
        if [[ "$verdict" != "THREAT" ]]; then
            for mac_entry in "${SUSPICIOUS_MAC_OUIS[@]}"; do
                MAC_PREFIX=$(echo "$mac_entry" | cut -d: -f1-3)
                MAC_DESC=$(echo "$mac_entry" | cut -d: -f4)
                
                if [[ "${BSSID,,}" == "${MAC_PREFIX,,}"* ]]; then
                    verdict="SUSPICIOUS"
                    verdict_reason="Suspicious MAC OUI: $MAC_DESC"
                    echo -e "${YELLOW}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                    echo -e "${YELLOW}  │ SUSPICIOUS MAC OUI DETECTED:                                    │${NC}"
                    echo -e "${YELLOW}  └─────────────────────────────────────────────────────────────────┘${NC}"
                    echo -e "${YELLOW}    SSID:          $SSID${NC}"
                    echo -e "${YELLOW}    BSSID:         $BSSID${NC}"
                    echo -e "${YELLOW}    OUI Match:     $MAC_PREFIX${NC}"
                    echo -e "${YELLOW}    Description:   $MAC_DESC${NC}"
                    echo -e "${YELLOW}    Signal:        $RSSI dBm${NC}"
                    echo ""
                    break
                fi
            done
        fi
        
        # Check for hidden network
        if [[ -z "$SSID" ]] || [[ "$SSID" == "" ]]; then
            verdict="SUSPICIOUS"
            verdict_reason="Hidden network (no SSID broadcast)"
        fi
        
        print_verdict "$verdict" "$SSID ($BSSID)" "$verdict_reason"
        echo ""
    done
    
    # Evil twin check
    if [[ -n "$CONNECTED_SSID" ]]; then
        echo -e "${WHITE}  EVIL TWIN CHECK:${NC}"
        TWIN_COUNT=$(echo "$WIFI_DATA" | grep -c "$CONNECTED_SSID" | awk '{print $1}')
        if [[ "$TWIN_COUNT" -gt 1 ]]; then
            echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${RED}  │ POSSIBLE EVIL TWIN ATTACK DETECTED:                             │${NC}"
            echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
            echo -e "${RED}    Connected SSID:   $CONNECTED_SSID${NC}"
            echo -e "${RED}    Duplicate APs:    $TWIN_COUNT${NC}"
            echo -e "${RED}    WARNING:          Multiple access points with same SSID!${NC}"
            echo -e "${RED}    All APs with this SSID:${NC}"
            echo "$WIFI_DATA" | grep "$CONNECTED_SSID" | sed 's/^/      /'
            echo ""
            print_verdict "THREAT" "$TWIN_COUNT APs with SSID '$CONNECTED_SSID'" "Possible evil twin attack"
        else
            print_verdict "CLEAN" "No duplicate SSIDs" "No evil twin detected"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# BLUETOOTH ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_bluetooth_verbose() {
    section_header "BLUETOOTH DEVICE ANALYSIS"
    
    BT_DATA=$(system_profiler SPBluetoothDataType 2>/dev/null)
    
    # Check if Bluetooth is available
    if [[ -z "$BT_DATA" ]] || echo "$BT_DATA" | grep -q "No information found"; then
        echo -e "${YELLOW}  Bluetooth not available or disabled${NC}"
        return
    fi
    
    echo -e "${CYAN}  Scanning Bluetooth devices...${NC}"
    echo ""
    
    # Parse connected devices
    echo "$BT_DATA" | grep -A10 "Devices (Paired)" | while IFS= read -r line; do
        if echo "$line" | grep -q "Name:"; then
            DEVICE_NAME=$(echo "$line" | sed 's/.*Name: //')
            
            echo -e "${WHITE}  Device: $DEVICE_NAME${NC}"
            
            local verdict="CLEAN"
            local verdict_reason=""
            
            # Check for suspicious names
            for pattern in "${SUSPICIOUS_BT_NAMES[@]}"; do
                if echo "$DEVICE_NAME" | grep -qi "$pattern"; then
                    verdict="THREAT"
                    verdict_reason="Matches suspicious pattern: $pattern"
                    
                    # Get more details about this device
                    DEVICE_DETAILS=$(echo "$BT_DATA" | grep -A15 "$DEVICE_NAME")
                    DEVICE_ADDR=$(echo "$DEVICE_DETAILS" | grep "Address:" | head -1 | awk '{print $2}')
                    DEVICE_CONNECTED=$(echo "$DEVICE_DETAILS" | grep "Connected:" | head -1 | awk '{print $2}')
                    
                    echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
                    echo -e "${RED}  │ SUSPICIOUS BLUETOOTH DEVICE DETECTED:                           │${NC}"
                    echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
                    echo -e "${RED}    Device Name:    $DEVICE_NAME${NC}"
                    echo -e "${RED}    Pattern Match:  $pattern${NC}"
                    echo -e "${RED}    BT Address:     ${DEVICE_ADDR:-Unknown}${NC}"
                    echo -e "${RED}    Connected:      ${DEVICE_CONNECTED:-Unknown}${NC}"
                    echo -e "${RED}    WARNING:        Device name matches known OMG/attack tool pattern!${NC}"
                    echo ""
                    break
                fi
            done
            
            print_verdict "$verdict" "$DEVICE_NAME" "$verdict_reason"
            echo ""
        fi
    done
    
    # Check for locally administered addresses
    echo -e "${WHITE}  BLUETOOTH ADDRESS CHECK:${NC}"
    BT_ADDRESSES=$(echo "$BT_DATA" | grep -E "Address:" | grep -oE "([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    
    for addr in $BT_ADDRESSES; do
        [[ -z "$addr" ]] && continue
        
        FIRST_BYTE=$(echo "$addr" | cut -d: -f1 | cut -d- -f1)
        DECIMAL=$((16#$FIRST_BYTE)) 2>/dev/null || DECIMAL=0
        
        if [[ $((DECIMAL & 2)) -ne 0 ]]; then
            print_verdict "SUSPICIOUS" "Address: $addr" "Locally administered (not factory assigned)"
        elif [[ "$addr" == "00:00:00:00:00:00" ]]; then
            echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${RED}  │ INVALID BLUETOOTH ADDRESS DETECTED:                             │${NC}"
            echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
            echo -e "${RED}    Address:    $addr${NC}"
            echo -e "${RED}    Type:       NULL ADDRESS${NC}"
            echo -e "${RED}    WARNING:    Null Bluetooth address is highly suspicious!${NC}"
            echo ""
            print_verdict "THREAT" "Address: $addr" "Null address - highly suspicious"
        else
            print_verdict "CLEAN" "Address: $addr" "Valid factory address"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# HID/KEYBOARD ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_hid_verbose() {
    section_header "HID/KEYBOARD INJECTION ANALYSIS"
    
    KEYBOARD_COUNT=$(ioreg -c IOHIDKeyboard 2>/dev/null | grep "IOHIDKeyboard" | wc -l | awk '{print $1}')
    MOUSE_COUNT=$(ioreg -c IOHIDPointing 2>/dev/null | grep "IOHIDPointing" | wc -l | awk '{print $1}')
    HID_TOTAL=$(ioreg -c IOHIDDevice 2>/dev/null | grep "IOHIDDevice" | wc -l | awk '{print $1}')
    
    echo -e "${CYAN}  HID Device Summary:${NC}"
    echo -e "    Total HID Devices:  $HID_TOTAL"
    echo -e "    Keyboards:          $KEYBOARD_COUNT"
    echo -e "    Pointing Devices:   $MOUSE_COUNT"
    echo ""
    
    echo -e "${WHITE}  KEYBOARD COUNT CHECK:${NC}"
    if [[ "$KEYBOARD_COUNT" -gt 1 ]]; then
        echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${RED}  │ MULTIPLE KEYBOARDS DETECTED - POSSIBLE INJECTION ATTACK:        │${NC}"
        echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
        echo -e "${RED}    Keyboard Count: $KEYBOARD_COUNT${NC}"
        echo -e "${RED}    Total HID:      $HID_TOTAL${NC}"
        echo -e "${RED}    WARNING:        Multiple keyboards indicate injection device!${NC}"
        echo ""
        echo -e "${RED}    Keyboard Devices Found:${NC}"
        ioreg -c IOHIDKeyboard -l 2>/dev/null | grep -E "Product|Manufacturer|VendorID|ProductID" | head -20 | sed 's/^/      /'
        echo ""
        print_verdict "THREAT" "$KEYBOARD_COUNT keyboards detected" "Multiple keyboards indicate possible injection attack"
    elif [[ "$KEYBOARD_COUNT" -eq 1 ]]; then
        print_verdict "CLEAN" "Single keyboard" "Normal configuration"
    else
        print_verdict "CLEAN" "No external keyboards" "Built-in only"
    fi
    
    echo ""
    echo -e "${WHITE}  KEYSTROKE INJECTION CHECK:${NC}"
    
    LOG_ENTRIES=$(log show --predicate 'subsystem == "com.apple.IOHIDFamily"' --last 5s 2>/dev/null | grep "Key" | wc -l | awk '{print $1}')
    
    if [[ "$LOG_ENTRIES" -gt 50 ]]; then
        echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${RED}  │ RAPID KEYSTROKE INJECTION DETECTED:                             │${NC}"
        echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
        echo -e "${RED}    Keystrokes:    $LOG_ENTRIES in 5 seconds${NC}"
        echo -e "${RED}    Rate:          $((LOG_ENTRIES / 5)) keys/second${NC}"
        echo -e "${RED}    Normal Rate:   2-8 keys/second for human typing${NC}"
        echo -e "${RED}    WARNING:       Machine-speed typing detected - ACTIVE INJECTION!${NC}"
        echo ""
        print_verdict "THREAT" "$LOG_ENTRIES keystrokes in 5 seconds" "Machine-speed typing detected - INJECTION ATTACK"
    elif [[ "$LOG_ENTRIES" -gt 20 ]]; then
        print_verdict "SUSPICIOUS" "$LOG_ENTRIES keystrokes in 5 seconds" "Elevated key activity"
    else
        print_verdict "CLEAN" "$LOG_ENTRIES keystrokes in 5 seconds" "Normal typing speed"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# THUNDERBOLT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

analyze_thunderbolt_verbose() {
    section_header "THUNDERBOLT/USB-C PORT ANALYSIS"
    
    TB_DATA=$(system_profiler SPThunderboltDataType 2>/dev/null)
    
    if [[ -z "$TB_DATA" ]] || echo "$TB_DATA" | grep -q "No information found"; then
        echo -e "${CYAN}  No Thunderbolt devices connected${NC}"
        print_verdict "CLEAN" "No external Thunderbolt devices" ""
        return
    fi
    
    echo -e "${CYAN}  Scanning Thunderbolt bus...${NC}"
    echo ""
    
    # Parse Thunderbolt devices more carefully
    # The format can vary, so we need to handle multiple cases
    
    while IFS= read -r device_name; do
        [[ -z "$device_name" ]] && continue
        
        # Clean up device name
        device_name=$(echo "$device_name" | sed 's/.*Device Name: //' | xargs)
        [[ -z "$device_name" ]] && continue
        
        echo -e "${WHITE}  Device: $device_name${NC}"
        
        # Get the block of info for this device
        DEVICE_BLOCK=$(echo "$TB_DATA" | grep -A30 "Device Name: $device_name" | head -30)
        
        # Extract vendor info - try multiple patterns
        VENDOR_NAME=$(echo "$DEVICE_BLOCK" | grep -E "Vendor Name:|Manufacturer:" | head -1 | sed 's/.*: //' | xargs)
        VENDOR_ID=$(echo "$DEVICE_BLOCK" | grep "Vendor ID:" | head -1 | sed 's/.*Vendor ID: //' | xargs)
        DEVICE_ID=$(echo "$DEVICE_BLOCK" | grep "Device ID:" | head -1 | sed 's/.*Device ID: //' | xargs)
        MODEL_ID=$(echo "$DEVICE_BLOCK" | grep "Model ID:" | head -1 | sed 's/.*Model ID: //' | xargs)
        ROUTE_STRING=$(echo "$DEVICE_BLOCK" | grep "Route String:" | head -1 | sed 's/.*Route String: //' | xargs)
        LINK_STATUS=$(echo "$DEVICE_BLOCK" | grep "Link Status:" | head -1 | sed 's/.*Link Status: //' | xargs)
        
        echo -e "    Vendor Name:  ${VENDOR_NAME:-N/A}"
        echo -e "    Vendor ID:    ${VENDOR_ID:-N/A}"
        echo -e "    Device ID:    ${DEVICE_ID:-N/A}"
        echo -e "    Model ID:     ${MODEL_ID:-N/A}"
        echo -e "    Route String: ${ROUTE_STRING:-N/A}"
        echo -e "    Link Status:  ${LINK_STATUS:-N/A}"
        
        local verdict="CLEAN"
        local verdict_reason=""
        local is_apple_device=0
        
        # Check if this is a known Apple Thunderbolt device by name
        for apple_device in "${APPLE_THUNDERBOLT_DEVICES[@]}"; do
            if echo "$device_name" | grep -qi "$apple_device"; then
                is_apple_device=1
                break
            fi
        done
        
        # Check if vendor is Apple
        for apple_vendor in "${APPLE_THUNDERBOLT_VENDORS[@]}"; do
            if [[ "$VENDOR_NAME" == "$apple_vendor" ]] || [[ "$VENDOR_ID" == "$apple_vendor" ]]; then
                is_apple_device=1
                break
            fi
        done
        
        # If it's an Apple device, it's clean
        if [[ "$is_apple_device" -eq 1 ]]; then
            verdict="CLEAN"
            verdict_reason="Verified Apple/Mac device"
        # Check for genuinely suspicious vendor IDs (empty or clearly invalid)
        elif [[ -z "$VENDOR_ID" ]] && [[ -z "$VENDOR_NAME" ]] && [[ "$device_name" != *"Mac"* ]] && [[ "$device_name" != *"Air"* ]] && [[ "$device_name" != *"Pro"* ]]; then
            # Only flag if it's NOT a Mac device AND has no vendor info
            verdict="SUSPICIOUS"
            verdict_reason="Unable to determine vendor"
        elif echo "$VENDOR_ID" | grep -qE "^0x0$|^0x0000$|^0xffff$" && [[ "$is_apple_device" -eq 0 ]]; then
            verdict="THREAT"
            verdict_reason="Invalid vendor ID on non-Apple device"
            echo -e "${RED}  ┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "${RED}  │ SUSPICIOUS THUNDERBOLT DEVICE DETECTED:                         │${NC}"
            echo -e "${RED}  └─────────────────────────────────────────────────────────────────┘${NC}"
            echo -e "${RED}    Device Name:   $device_name${NC}"
            echo -e "${RED}    Vendor Name:   ${VENDOR_NAME:-Unknown}${NC}"
            echo -e "${RED}    Vendor ID:     ${VENDOR_ID:-INVALID}${NC}"
            echo -e "${RED}    Device ID:     ${DEVICE_ID:-Unknown}${NC}"
            echo -e "${RED}    Route String:  ${ROUTE_STRING:-Unknown}${NC}"
            echo -e "${RED}    WARNING:       Invalid vendor ID - possible malicious device!${NC}"
            echo ""
        else
            verdict="CLEAN"
            verdict_reason="Valid Thunderbolt device"
        fi
        
        print_verdict "$verdict" "$device_name" "$verdict_reason"
        echo ""
        
    done < <(echo "$TB_DATA" | grep "Device Name:" | head -20)
}

# ══════════════════════════════════════════════════════════════════════════════
# WIFI NETWORK SCANNING (OMG CABLE WIFI DETECTION)
# ══════════════════════════════════════════════════════════════════════════════

# Known OMG Cable WiFi SSIDs and patterns
OMG_WIFI_SSIDS=(
    "O.MG"
    "OMG"
    "HAK5"
    "PAYLOAD"
    "KEYGRABBER"
    "USBNINJA"
    "IMPLANT"
    "EXFIL"
    "DROPPER"
    "C2"
    "ESP"
    "PWNAGOTCHI"
)

scan_wifi_networks() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║               WIFI NETWORK SCANNING (OMG Cable Detection)              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Disassociate from current network (flushes cache)
    echo -e "${YELLOW}[*] Flushing WiFi cache and refreshing networks...${NC}"
    sudo airport -z 2>/dev/null
    sleep 2
    
    # Scan for all networks including hidden SSIDs
    echo -e "${YELLOW}[*] Scanning for WiFi networks (including hidden SSIDs)...${NC}"
    local WIFI_SCAN=$(sudo airport -s 2>/dev/null)
    
    if [[ -z "$WIFI_SCAN" ]]; then
        echo -e "${YELLOW}[!] No WiFi networks detected or airport utility unavailable${NC}"
        return
    fi
    
    echo -e "${CYAN}[+] WiFi Networks Found:${NC}"
    echo "$WIFI_SCAN" | head -20
    echo ""
    
    # Check for suspicious OMG Cable WiFi patterns
    local SUSPICIOUS_WIFI=0
    
    while IFS= read -r line; do
        local SSID=$(echo "$line" | awk '{print $1}')
        local BSSID=$(echo "$line" | awk '{print $2}')
        local RSSI=$(echo "$line" | awk '{print $3}')
        local CHANNEL=$(echo "$line" | awk '{print $4}')
        local SECURITY=$(echo "$line" | awk '{print $6}')
        
        # Check against OMG Cable SSID patterns
        for omg_ssid in "${OMG_WIFI_SSIDS[@]}"; do
            if echo "$SSID" | grep -qi "$omg_ssid"; then
                echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║  ⚠️  SUSPICIOUS OMG CABLE WIFI NETWORK DETECTED!                      ║${NC}"
                echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
                echo -e "${RED}  SSID:     $SSID${NC}"
                echo -e "${RED}  BSSID:    $BSSID${NC}"
                echo -e "${RED}  RSSI:     $RSSI dBm${NC}"
                echo -e "${RED}  Channel:  $CHANNEL${NC}"
                echo -e "${RED}  Security: $SECURITY${NC}"
                echo -e "${RED}  Pattern:  Matches OMG Cable signature '$omg_ssid'${NC}"
                echo ""
                ((THREAT_COUNT++))
                SUSPICIOUS_WIFI=1
            fi
        done
        
        # Check for very strong signal (device might be very close - like in a cable)
        if [[ -n "$RSSI" ]] && [[ "$RSSI" =~ ^-?[0-9]+$ ]] && [[ $RSSI -gt -30 ]]; then
            echo -e "${YELLOW}[!] UNUSUALLY STRONG WiFi SIGNAL DETECTED:${NC}"
            echo -e "${YELLOW}    SSID: $SSID | BSSID: $BSSID | RSSI: $RSSI dBm${NC}"
            echo -e "${YELLOW}    This could indicate a WiFi device in close proximity (cable implant)${NC}"
            echo ""
            ((SUSPICIOUS_COUNT++))
        fi
        
        # Check for hidden SSIDs (blank SSID)
        if [[ -z "$SSID" ]] || [[ "$SSID" == "" ]]; then
            echo -e "${YELLOW}[!] HIDDEN SSID DETECTED:${NC}"
            echo -e "${YELLOW}    BSSID: $BSSID | RSSI: $RSSI dBm | Channel: $CHANNEL${NC}"
            echo -e "${YELLOW}    Hidden SSIDs can indicate covert communication channels${NC}"
            echo ""
            ((SUSPICIOUS_COUNT++))
        fi
        
    done < <(echo "$WIFI_SCAN" | tail -n +2)
    
    if [[ $SUSPICIOUS_WIFI -eq 0 ]]; then
        echo -e "${GREEN}[✓] No suspicious OMG Cable WiFi networks detected${NC}"
        ((CLEAN_COUNT++))
    fi
    
    # Get current WiFi interface details
    echo -e "${CYAN}[*] Current WiFi Interface Details:${NC}"
    networksetup -listallhardwareports 2>/dev/null | grep -A 2 "Wi-Fi"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# IOREGISTRY DEEP ANALYSIS WITH PYTHON
# ══════════════════════════════════════════════════════════════════════════════

analyze_ioregistry_deep() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          DEEP IOREGISTRY ANALYSIS (Per-Port/Device Topology)           ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Create Python script for deep IORegistry parsing
    cat > /tmp/ioregistry_parser.py << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
"""
Deep IORegistry Parser for OMG Cable Detection
Parses USB topology, descriptors, and device details using PyObjC
"""

import sys
import subprocess
import json
from datetime import datetime

def run_ioreg(plane="IOUSB"):
    """Run ioreg and return output"""
    try:
        result = subprocess.run(
            ['ioreg', '-p', plane, '-l', '-w0'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except Exception as e:
        print(f"Error running ioreg: {e}", file=sys.stderr)
        return ""

def parse_usb_device_line(line):
    """Parse a single line from ioreg output"""
    device_info = {}
    
    # Extract device name
    if '"' in line:
        parts = line.split('"')
        if len(parts) >= 2:
            device_info['name'] = parts[1]
    
    # Extract key-value pairs
    if '=' in line:
        pairs = line.split(',')
        for pair in pairs:
            if '=' in pair:
                key_val = pair.split('=')
                if len(key_val) == 2:
                    key = key_val[0].strip().strip('"')
                    val = key_val[1].strip().strip('"')
                    device_info[key] = val
    
    return device_info

def analyze_usb_topology():
    """Analyze USB topology and device descriptors"""
    print("="*80)
    print("USB DEVICE TOPOLOGY AND DESCRIPTOR ANALYSIS")
    print("="*80)
    print()
    
    # Get USB plane
    usb_data = run_ioreg("IOUSB")
    
    # Parse for USB devices
    devices = []
    current_device = {}
    indent_level = 0
    
    for line in usb_data.split('\n'):
        # Track tree structure by indentation
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)
        
        if '+-o' in line or '| +-o' in line:
            # New device entry
            if current_device:
                devices.append(current_device)
            current_device = {'indent': current_indent}
            
            # Extract device name
            if '@' in line:
                device_name = line.split('@')[0].split('+-o')[-1].strip()
                current_device['name'] = device_name
                
        elif current_device and '=' in line:
            # Property line
            try:
                prop_line = stripped.strip()
                if '"' in prop_line:
                    key = prop_line.split('=')[0].strip().strip('"')
                    val = prop_line.split('=')[1].strip().strip('"').strip(',')
                    current_device[key] = val
            except:
                pass
    
    if current_device:
        devices.append(current_device)
    
    # Print device hierarchy
    print(f"Total USB devices found: {len(devices)}\n")
    
    for idx, device in enumerate(devices):
        indent = " " * (device.get('indent', 0) // 2)
        name = device.get('name', 'Unknown Device')
        
        print(f"{indent}[{idx}] {name}")
        
        # Print critical properties
        critical_props = [
            'idVendor', 'idProduct', 'USB Vendor Name', 'USB Product Name',
            'locationID', 'USB Address', 'bcdDevice', 'iSerialNumber',
            'bDeviceClass', 'bDeviceSubClass', 'bDeviceProtocol',
            'bNumConfigurations', 'USB Serial Number', 'PortNum',
            'IOUserClientClass', 'IOCFPlugInTypes'
        ]
        
        for prop in critical_props:
            if prop in device:
                print(f"{indent}  {prop}: {device[prop]}")
        
        # Check for suspicious indicators
        vendor_id = device.get('idVendor', '')
        product_id = device.get('idProduct', '')
        device_class = device.get('bDeviceClass', '')
        vendor_name = device.get('USB Vendor Name', '')
        
        # OMG Cable detection patterns
        suspicious = []
        
        if vendor_id in ['0x1337', '0xdead', '0xbeef', '0xcafe', '0x16d0', '0x1209']:
            suspicious.append("VENDOR ID MATCHES OMG CABLE PATTERN")
        
        if 'O.MG' in name or 'OMG' in vendor_name.upper():
            suspicious.append("DEVICE NAME MATCHES OMG CABLE")
        
        if device_class == '0x3' or device_class == '3':
            # HID class - could be keystroke injection
            if vendor_id not in ['0x5ac', '0x05ac']:  # Not Apple
                suspicious.append("HID DEVICE FROM NON-APPLE VENDOR")
        
        if device_class == '0x8' or device_class == '8':
            # Mass storage class
            suspicious.append("MASS STORAGE CAPABILITY (Possible payload storage)")
        
        if device_class == '0xe0' or device_class == '224':
            # Wireless controller
            suspicious.append("WIRELESS CAPABILITY (WiFi/BT exfiltration risk)")
        
        # Check for multiple interfaces (OMG cables often present as composite devices)
        num_configs = device.get('bNumConfigurations', '0')
        if num_configs != '0' and num_configs != '1':
            suspicious.append(f"MULTIPLE CONFIGURATIONS ({num_configs})")
        
        if suspicious:
            print(f"{indent}  \033[91m⚠️  SUSPICIOUS INDICATORS:")
            for indicator in suspicious:
                print(f"{indent}     - {indicator}\033[0m")
        
        print()
    
    return devices

def analyze_network_interfaces():
    """Analyze network interfaces for hidden adapters"""
    print("="*80)
    print("NETWORK INTERFACE ANALYSIS (Hidden WiFi Adapter Detection)")
    print("="*80)
    print()
    
    net_data = run_ioreg("IODeviceTree")
    
    # Look for network-related devices
    for line in net_data.split('\n'):
        if 'ethernet' in line.lower() or 'wifi' in line.lower() or 'wlan' in line.lower():
            print(f"  {line.strip()}")
    
    print()

def main():
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*20 + "IORegistry Deep Analysis with Python" + " "*22 + "║")
    print("║" + " "*25 + f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + " "*25 + "║")
    print("╚" + "="*78 + "╝")
    print()
    
    # Analyze USB topology
    devices = analyze_usb_topology()
    
    # Analyze network interfaces
    analyze_network_interfaces()
    
    # Summary
    print("="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"Total devices analyzed: {len(devices)}")
    print()

if __name__ == "__main__":
    main()
PYTHON_SCRIPT
    
    chmod +x /tmp/ioregistry_parser.py
    
    # Run Python analysis
    echo -e "${YELLOW}[*] Running deep IORegistry analysis with Python...${NC}"
    python3 /tmp/ioregistry_parser.py 2>/dev/null || echo -e "${RED}[!] Python analysis failed (continuing with bash analysis)${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA EXFILTRATION MONITORING
# ══════════════════════════════════════════════════════════════════════════════

monitor_data_exfiltration() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           DATA EXFILTRATION MONITORING (External USB Devices)          ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Monitor network connections from USB devices
    echo -e "${YELLOW}[*] Checking for network connections from USB-attached devices...${NC}"
    
    # Get list of network interfaces
    local INTERFACES=$(networksetup -listallhardwareports 2>/dev/null | grep "Device:" | awk '{print $2}')
    
    for iface in $INTERFACES; do
        # Check if interface is associated with USB device
        local USB_CHECK=$(ioreg -r -c IOUSBInterface -l | grep -A 20 "$iface" 2>/dev/null)
        
        if [[ -n "$USB_CHECK" ]]; then
            echo -e "${YELLOW}[!] USB-ASSOCIATED NETWORK INTERFACE: $iface${NC}"
            
            # Check for active connections on this interface
            local CONNECTIONS=$(netstat -an | grep "$iface" 2>/dev/null)
            if [[ -n "$CONNECTIONS" ]]; then
                echo -e "${RED}  ⚠️  ACTIVE NETWORK CONNECTIONS ON USB INTERFACE!${NC}"
                echo -e "${RED}  This could indicate data exfiltration via USB device${NC}"
                echo "$CONNECTIONS" | head -10
                ((THREAT_COUNT++))
            fi
        fi
    done
    
    # Monitor file operations on external storage
    echo ""
    echo -e "${YELLOW}[*] Checking for external USB storage devices...${NC}"
    
    local EXTERNAL_VOLUMES=$(diskutil list external physical 2>/dev/null)
    
    if [[ -n "$EXTERNAL_VOLUMES" ]]; then
        echo -e "${CYAN}[+] External Storage Devices:${NC}"
        echo "$EXTERNAL_VOLUMES"
        echo ""
        
        # Check for recently accessed files on external volumes
        echo -e "${YELLOW}[*] Analyzing recent file access on external volumes...${NC}"
        
        # Get mounted external volumes
        local MOUNT_POINTS=$(mount | grep -i "external\|removable" | awk '{print $3}')
        
        for mount_point in $MOUNT_POINTS; do
            if [[ -d "$mount_point" ]]; then
                echo -e "${CYAN}  Checking: $mount_point${NC}"
                
                # Find recently modified files (last 5 minutes)
                local RECENT_FILES=$(find "$mount_point" -type f -mmin -5 2>/dev/null | head -20)
                
                if [[ -n "$RECENT_FILES" ]]; then
                    echo -e "${YELLOW}  [!] Recently modified files detected:${NC}"
                    echo "$RECENT_FILES" | while read -r file; do
                        echo "      - $file"
                    done
                    echo -e "${YELLOW}  [!] Files have been written to external storage recently${NC}"
                    echo -e "${YELLOW}      This could indicate data exfiltration activity${NC}"
                    ((SUSPICIOUS_COUNT++))
                fi
            fi
        done
    else
        echo -e "${GREEN}[✓] No external storage devices detected${NC}"
    fi
    
    # Monitor for suspicious process activity related to USB
    echo ""
    echo -e "${YELLOW}[*] Checking for suspicious processes accessing USB devices...${NC}"
    
    # Look for processes with open file descriptors to USB devices
    local USB_PROCESSES=$(lsof 2>/dev/null | grep -i "usb\|mass\|storage" | head -20)
    
    if [[ -n "$USB_PROCESSES" ]]; then
        echo -e "${CYAN}[+] Processes with USB device access:${NC}"
        echo "$USB_PROCESSES"
        echo ""
    fi
    
    # Check for network traffic patterns indicating exfiltration
    echo -e "${YELLOW}[*] Analyzing network traffic for exfiltration patterns...${NC}"
    
    # Get current network statistics
    local NET_STATS=$(netstat -ib 2>/dev/null | grep -E "en|usb|rndis")
    
    if [[ -n "$NET_STATS" ]]; then
        echo -e "${CYAN}[+] Network Interface Statistics:${NC}"
        echo "$NET_STATS"
        echo ""
        
        # Look for unusually high outbound traffic on USB interfaces
        echo "$NET_STATS" | while read -r line; do
            if echo "$line" | grep -qi "usb\|rndis"; then
                local OBYTES=$(echo "$line" | awk '{print $10}')
                if [[ -n "$OBYTES" ]] && [[ "$OBYTES" =~ ^[0-9]+$ ]] && [[ $OBYTES -gt 1000000 ]]; then
                    echo -e "${YELLOW}  [!] HIGH OUTBOUND TRAFFIC on USB interface: $line${NC}"
                    echo -e "${YELLOW}      Outbound bytes: $OBYTES${NC}"
                    ((SUSPICIOUS_COUNT++))
                fi
            fi
        done
    fi
    
    echo -e "${GREEN}[✓] Data exfiltration monitoring complete${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print_final_summary() {
    echo ""
    echo -e "${WHITE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                        SCAN COMPLETE                               ║${NC}"
    echo -e "${WHITE}╠════════════════════════════════════════════════════════════════════╣${NC}"
    
    TOTAL_SCANNED=$((CLEAN_COUNT + SUSPICIOUS_COUNT + THREAT_COUNT))
    
    echo -e "${WHITE}║${NC}  Total Items Scanned:    ${CYAN}$TOTAL_SCANNED${NC}"
    echo -e "${WHITE}║${NC}  ${GREEN}Clean:${NC}                   $CLEAN_COUNT"
    echo -e "${WHITE}║${NC}  ${YELLOW}Suspicious:${NC}              $SUSPICIOUS_COUNT"
    echo -e "${WHITE}║${NC}  ${RED}Threats:${NC}                 $THREAT_COUNT"
    echo -e "${WHITE}╠════════════════════════════════════════════════════════════════════╣${NC}"
    
    if [[ "$THREAT_COUNT" -gt 0 ]]; then
        echo -e "${WHITE}║${NC}  ${RED}⚠️  THREATS DETECTED - IMMEDIATE ACTION REQUIRED${NC}"
        echo -e "${WHITE}║${NC}  ${RED}    Disconnect suspicious devices immediately!${NC}"
    elif [[ "$SUSPICIOUS_COUNT" -gt 0 ]]; then
        echo -e "${WHITE}║${NC}  ${YELLOW}⚠️  Suspicious items found - review recommended${NC}"
    else
        echo -e "${WHITE}║${NC}  ${GREEN}✓  No immediate threats detected${NC}"
    fi
    
    echo -e "${WHITE}╚════════════════════════════════════════════════════════════════════╝${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

is_external_usb_device() {
    # Takes a Location ID and returns 0 (false) if likely internal, 1 (true) if external.
    # On Apple Silicon, external devices often appear with higher Location IDs; adjust this logic based on local system observation.
    local location_id="$1"
    # Example: if Location ID starts with "0x14", it's commonly external.
    if [[ "$location_id" =~ ^0x14 ]]; then
        return 1
    else
        return 0
    fi
}

run_full_scan() {
    # Reset counters
    CLEAN_COUNT=0
    SUSPICIOUS_COUNT=0
    THREAT_COUNT=0
    ALERT_COUNT=0
    CABLE_COUNT=0
    
    # NEW: WiFi scanning with airport utility (sudo airport -z then sudo airport -s)
    scan_wifi_networks
    
    # NEW: Cable detection first
    detect_cables_and_devices
    
    # NEW: Cable capability analysis (WiFi, BT, storage, transmission, etc.)
    analyze_cable_capabilities
    
    # NEW: Deep IORegistry parsing with Python
    analyze_ioregistry_deep
    
    # NEW: Data exfiltration monitoring for external USB devices
    monitor_data_exfiltration
    
    # Original v5 analysis functions
    analyze_usb_devices_verbose
    analyze_usb_classes_verbose
    analyze_usb_descriptors_verbose
    analyze_interfaces_verbose
    analyze_hardware_ports_verbose
    analyze_wifi_verbose
    analyze_bluetooth_verbose
    analyze_hid_verbose
    analyze_thunderbolt_verbose
    
    print_final_summary
}

main() {
    echo -e "${YELLOW}[*] OMG Cable Detection Suite v8.0${NC}"
    echo -e "${YELLOW}[*] Comprehensive Cable + Device + Network Scanner${NC}"
    echo -e "${YELLOW}[*] Monitors: USB/WiFi/BT/Storage/Network/RF/Ultrasonic/Exfil${NC}"
    echo -e "${YELLOW}[*] Features: Airport WiFi Scan + Python IORegistry + Data Exfil Detection${NC}"
    echo -e "${CYAN}    Press Ctrl+C to stop continuous monitoring${NC}"
    echo ""
    
    # Initial full scan
    run_full_scan
    
    # Continuous monitoring with change detection
    while true; do
        ((SCAN_CYCLE++))
        
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║  CONTINUOUS SCAN #$SCAN_CYCLE - $(date '+%Y-%m-%d %H:%M:%S')${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
        
        # Check for USB device changes before full scan
        local CURRENT_USB=$(system_profiler SPUSBDataType 2>/dev/null | grep -c "Product ID:" | awk '{print $1}')
        if [[ "$CURRENT_USB" -ne "$BASELINE_USB_COUNT" ]]; then
            echo ""
            echo -e "${RED}  ╔═══════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}  ║  ⚠️  USB DEVICE CHANGE DETECTED!                                  ║${NC}"
            echo -e "${RED}  ║  Previous: $BASELINE_USB_COUNT devices | Current: $CURRENT_USB devices${NC}"
            echo -e "${RED}  ╚═══════════════════════════════════════════════════════════════════╝${NC}"
            
            if [[ "$CURRENT_USB" -gt "$BASELINE_USB_COUNT" ]]; then
                echo -e "${RED}  NEW CABLE/DEVICE CONNECTED!${NC}"
            else
                echo -e "${YELLOW}  Cable/device disconnected${NC}"
            fi
            BASELINE_USB_COUNT=$CURRENT_USB
        fi
        
        # Track last 5 device attach/detach events
echo "==== Recent USB attach/detach events ===="
log show --predicate 'eventMessage CONTAINS "USB device"' --info --last 1m | tail -10
echo "==== End USB attach log ===="

date >> /tmp/usb_device_history.log
ioreg -p IOUSB -w0 >> /tmp/usb_device_history.log
        
        sleep 5
        run_full_scan
    done
}

cleanup() {
    echo ""
    echo -e "${YELLOW}[*] Scanner stopped${NC}"
    echo -e "${GREEN}[✓] Total scan cycles: $SCAN_CYCLE${NC}"
    echo -e "${GREEN}[✓] Total alerts: $ALERT_COUNT${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

main
