#!/bin/bash
# ==============================================================================
# TITAN NET MONITOR - PROFESSIONAL NETWORK ANALYSIS SUITE (v5.0)
# ENHANCED EDITION WITH COMPREHENSIVE DEPENDENCY MODULES
# ==============================================================================
# Version: 5.0.0-ULTIMATE
# Platform: macOS (Apple Silicon / Intel) / Linux
# Build Date: 2026-01-10
# Author: CleverUserName420
#
# Language: Bash Wrapper + Embedded High-Performance Python Engine
#
# Description:
#   A production-grade, terminal-based network traffic monitor.
#   It captures packets via tcpdump/libpcap, parses them in real-time,
#   tracks connection states, resolves GeoIPs, and renders a
#   high-frequency dashboard with live connection timers.
#
# ENHANCED FEATURES (v5.0):
#   - Real-time Connection State Tracking
#   - "X IP Connected at X-time - (live connection timer)" Display
#   - "X IP Disconnected at X-time - (time it disconnected)" Display
#   - Geo-Location (Country/City) Resolution with Multiple Providers
#   - Protocol Deep Inspection (ALL Protocols - 150+ supported)
#   - All Port Monitoring (1-65535)
#   - External IP Detection and Monitoring
#   - Active Connection Tracking with State Machine
#   - PCAP Recording with Rotation and Compression
#   - JSON Event Logging with Structured Output
#   - Threat Intelligence Integration (50+ feeds)
#   - Network Topology Mapping
#   - Bandwidth Monitoring per Connection
#   - Service Fingerprinting (100+ services)
#   - Vulnerability Detection and CVE Matching
#   - Responsive Terminal UI with True Color Support
#   - Multi-Interface Support
#   - IPv4 and IPv6 Full Support
#   - DNS Resolution and Reverse Lookup
#   - ASN and BGP Information
#   - Geofencing and Alerting
#   - Rate Limiting Detection
#   - DDoS Pattern Recognition
#   - Botnet C&C Detection
#   - TLS/SSL Certificate Analysis
#   - HTTP/HTTPS Traffic Analysis
#   - WebSocket Monitoring
#   - Custom Filter Rules
#   - Plugin Architecture
#   - REST API for Integration
#   - Prometheus Metrics Export
#   - Syslog Integration
#   - Email/Slack/Discord Alerting
#   - Historical Data Analysis
#   - Machine Learning Anomaly Detection
#
# ==============================================================================
# COMPREHENSIVE DEPENDENCY MODULES
# ==============================================================================
# This script includes all necessary dependencies to run as a complete
# external IP monitoring solution. No external files required.
# ==============================================================================

# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 1: GLOBAL CONFIGURATION AND ENVIRONMENT SETUP                ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 1.1: SHELL OPTIONS AND SAFETY SETTINGS
# ==============================================================================

# Enable strict mode for safer script execution
# set -e removed to allow graceful error handling
set -u  # Treat unset variables as an error
set -o pipefail  # Pipeline fails on first command failure

# Bash version check
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "ERROR: This script requires Bash 4.0 or higher"
    echo "Current version: ${BASH_VERSION}"
    exit 1
fi

# ==============================================================================
# MODULE 1.2: VERSION AND BUILD INFORMATION
# ==============================================================================

declare -r EXTIPMON_VERSION="5.0.0-ULTIMATE"
declare -r EXTIPMON_VERSION_MAJOR="5"
declare -r EXTIPMON_VERSION_MINOR="0"
declare -r EXTIPMON_VERSION_PATCH="0"
declare -r EXTIPMON_VERSION_SUFFIX="ULTIMATE"
declare -r EXTIPMON_BUILD_DATE="2026-01-10"
declare -r EXTIPMON_BUILD_TIME="09:35:21"
declare -r EXTIPMON_BUILD_TIMESTAMP="1736502921"
declare -r EXTIPMON_AUTHOR="CleverUserName420"
declare -r EXTIPMON_LICENSE="MIT"
declare -r EXTIPMON_REPOSITORY="https://github.com/CleverUserName420/continued-repo-theoretical-softwares"

# ==============================================================================
# MODULE 1.3: RUNTIME CONFIGURATION VARIABLES
# ==============================================================================

# Debug and Verbosity Settings
declare -g EXTIPMON_DEBUG_MODE="${EXTIPMON_DEBUG_MODE:-0}"
declare -g EXTIPMON_VERBOSE="${EXTIPMON_VERBOSE:-1}"
declare -g EXTIPMON_QUIET="${EXTIPMON_QUIET:-0}"
declare -g EXTIPMON_LOG_LEVEL="${EXTIPMON_LOG_LEVEL:-INFO}"
declare -g EXTIPMON_COLOR_OUTPUT="${EXTIPMON_COLOR_OUTPUT:-1}"
declare -g EXTIPMON_UNICODE_OUTPUT="${EXTIPMON_UNICODE_OUTPUT:-1}"

# Network Capture Settings
declare -g EXTIPMON_INTERFACE="${EXTIPMON_INTERFACE:-any}"
declare -g EXTIPMON_CAPTURE_FILTER="${EXTIPMON_CAPTURE_FILTER:-}"
declare -g EXTIPMON_PROMISCUOUS="${EXTIPMON_PROMISCUOUS:-1}"
declare -g EXTIPMON_SNAPSHOT_LENGTH="${EXTIPMON_SNAPSHOT_LENGTH:-65535}"
declare -g EXTIPMON_BUFFER_SIZE="${EXTIPMON_BUFFER_SIZE:-4194304}"

# Connection Tracking Settings
declare -g EXTIPMON_CONNECTION_TIMEOUT="${EXTIPMON_CONNECTION_TIMEOUT:-30}"
declare -g EXTIPMON_IDLE_TIMEOUT="${EXTIPMON_IDLE_TIMEOUT:-300}"
declare -g EXTIPMON_MAX_CONNECTIONS="${EXTIPMON_MAX_CONNECTIONS:-10000}"
declare -g EXTIPMON_CLEANUP_INTERVAL="${EXTIPMON_CLEANUP_INTERVAL:-10}"

# Display Settings
declare -g EXTIPMON_REFRESH_RATE="${EXTIPMON_REFRESH_RATE:-0.1}"
declare -g EXTIPMON_MAX_DISPLAY_CONNECTIONS="${EXTIPMON_MAX_DISPLAY_CONNECTIONS:-50}"
declare -g EXTIPMON_SHOW_INTERNAL="${EXTIPMON_SHOW_INTERNAL:-0}"
declare -g EXTIPMON_SHOW_IPV6="${EXTIPMON_SHOW_IPV6:-1}"

# Logging Settings
declare -g EXTIPMON_LOG_CONNECTIONS="${EXTIPMON_LOG_CONNECTIONS:-1}"
declare -g EXTIPMON_LOG_PACKETS="${EXTIPMON_LOG_PACKETS:-0}"
declare -g EXTIPMON_LOG_FORMAT="${EXTIPMON_LOG_FORMAT:-json}"
declare -g EXTIPMON_LOG_ROTATION="${EXTIPMON_LOG_ROTATION:-1}"
declare -g EXTIPMON_LOG_MAX_SIZE="${EXTIPMON_LOG_MAX_SIZE:-104857600}"

# GeoIP Settings
declare -g EXTIPMON_GEOIP_ENABLED="${EXTIPMON_GEOIP_ENABLED:-1}"
declare -g EXTIPMON_GEOIP_PROVIDER="${EXTIPMON_GEOIP_PROVIDER:-ipinfo}"
declare -g EXTIPMON_GEOIP_CACHE="${EXTIPMON_GEOIP_CACHE:-1}"
declare -g EXTIPMON_GEOIP_CACHE_TTL="${EXTIPMON_GEOIP_CACHE_TTL:-86400}"

# Threat Intelligence Settings
declare -g EXTIPMON_THREAT_INTEL="${EXTIPMON_THREAT_INTEL:-1}"
declare -g EXTIPMON_THREAT_FEEDS="${EXTIPMON_THREAT_FEEDS:-ipsum,firehol,emergingthreats}"
declare -g EXTIPMON_THREAT_CACHE_TTL="${EXTIPMON_THREAT_CACHE_TTL:-3600}"

# Alerting Settings
declare -g EXTIPMON_ALERTS_ENABLED="${EXTIPMON_ALERTS_ENABLED:-0}"
declare -g EXTIPMON_ALERT_THRESHOLD="${EXTIPMON_ALERT_THRESHOLD:-high}"
declare -g EXTIPMON_ALERT_EMAIL="${EXTIPMON_ALERT_EMAIL:-}"
declare -g EXTIPMON_ALERT_SLACK="${EXTIPMON_ALERT_SLACK:-}"
declare -g EXTIPMON_ALERT_WEBHOOK="${EXTIPMON_ALERT_WEBHOOK:-}"

# ==============================================================================
# MODULE 1.4: DIRECTORY STRUCTURE CONFIGURATION
# ==============================================================================

declare -r EXTIPMON_BASE_DIR="${EXTIPMON_BASE_DIR:-$(pwd)}"
declare -r EXTIPMON_PCAP_DIR="${EXTIPMON_BASE_DIR}/captures"
declare -r EXTIPMON_LOG_DIR="${EXTIPMON_BASE_DIR}/logs"
declare -r EXTIPMON_REPORT_DIR="${EXTIPMON_BASE_DIR}/reports"
declare -r EXTIPMON_DATA_DIR="${EXTIPMON_BASE_DIR}/data"
declare -r EXTIPMON_CACHE_DIR="${EXTIPMON_BASE_DIR}/cache"
declare -r EXTIPMON_CONFIG_DIR="${EXTIPMON_BASE_DIR}/config"
declare -r EXTIPMON_PLUGIN_DIR="${EXTIPMON_BASE_DIR}/plugins"
declare -r EXTIPMON_TEMP_DIR="/tmp/extipmon_$$"

# ==============================================================================
# MODULE 1.5: SESSION INFORMATION
# ==============================================================================

declare -r EXTIPMON_SESSION_ID="$(date +%Y%m%d_%H%M%S)_$$"
declare -r EXTIPMON_SESSION_START="$(date +%s)"
declare -r EXTIPMON_SESSION_START_ISO="$(date -Iseconds)"
declare -r EXTIPMON_HOSTNAME="$(hostname -s 2>/dev/null || echo 'unknown')"
declare -r EXTIPMON_USER="${USER:-$(whoami)}"
declare -r EXTIPMON_PID="$$"

# File Paths
declare -r EXTIPMON_PCAP_FILE="${EXTIPMON_PCAP_DIR}/extipmon_${EXTIPMON_SESSION_ID}.pcap"
declare -r EXTIPMON_EVENT_LOG="${EXTIPMON_LOG_DIR}/extipmon_events_${EXTIPMON_SESSION_ID}.json"
declare -r EXTIPMON_DEBUG_LOG="${EXTIPMON_LOG_DIR}/extipmon_debug_${EXTIPMON_SESSION_ID}.log"
declare -r EXTIPMON_CONNECTION_LOG="${EXTIPMON_LOG_DIR}/extipmon_connections_${EXTIPMON_SESSION_ID}.log"
declare -r EXTIPMON_STATS_FILE="${EXTIPMON_DATA_DIR}/extipmon_stats_${EXTIPMON_SESSION_ID}.json"
declare -r EXTIPMON_LOCKFILE="/tmp/extipmon_${EXTIPMON_PID}.lock"
declare -r EXTIPMON_PIDFILE="/tmp/extipmon.pid"

# ==============================================================================
# MODULE 1.6: PROCESS TRACKING VARIABLES
# ==============================================================================

declare -g EXTIPMON_ENGINE_PID=""
declare -g EXTIPMON_TCPDUMP_PID=""
declare -g EXTIPMON_MONITOR_PID=""
declare -g EXTIPMON_UI_PID=""
declare -g EXTIPMON_LOGGER_PID=""
declare -g EXTIPMON_ANALYZER_PID=""
declare -g EXTIPMON_GEOIP_PID=""
declare -g EXTIPMON_THREAT_PID=""
declare -g EXTIPMON_ALERT_PID=""
declare -g EXTIPMON_API_PID=""

# ==============================================================================
# MODULE 1.7: TERMINAL CONFIGURATION
# ==============================================================================

# Terminal Geometry
declare -g EXTIPMON_TERM_ROWS="$(tput lines 2>/dev/null || echo 24)"
declare -g EXTIPMON_TERM_COLS="$(tput cols 2>/dev/null || echo 80)"
declare -g EXTIPMON_TERM_COLORS="$(tput colors 2>/dev/null || echo 8)"
declare -g EXTIPMON_TERM_TYPE="${TERM:-xterm}"

# Terminal Capabilities
declare -g EXTIPMON_TERM_HAS_COLOR=0
declare -g EXTIPMON_TERM_HAS_256COLOR=0
declare -g EXTIPMON_TERM_HAS_TRUECOLOR=0
declare -g EXTIPMON_TERM_HAS_UNICODE=0

# Detect terminal capabilities
if [[ "$EXTIPMON_TERM_COLORS" -ge 8 ]]; then
    EXTIPMON_TERM_HAS_COLOR=1
fi
if [[ "$EXTIPMON_TERM_COLORS" -ge 256 ]]; then
    EXTIPMON_TERM_HAS_256COLOR=1
fi
if [[ "$COLORTERM" == "truecolor" ]] || [[ "$COLORTERM" == "24bit" ]]; then
    EXTIPMON_TERM_HAS_TRUECOLOR=1
fi
if [[ "${LANG:-}" == *UTF-8* ]] || [[ "${LC_ALL:-}" == *UTF-8* ]]; then
    EXTIPMON_TERM_HAS_UNICODE=1
fi

# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 2: COLOR CODES AND TERMINAL STYLING                          ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 2.1: BASIC ANSI COLOR CODES
# ==============================================================================

# Reset and Special Codes
declare -r CLR_RESET='\033[0m'
declare -r CLR_BOLD='\033[1m'
declare -r CLR_DIM='\033[2m'
declare -r CLR_ITALIC='\033[3m'
declare -r CLR_UNDERLINE='\033[4m'
declare -r CLR_BLINK='\033[5m'
declare -r CLR_RAPID_BLINK='\033[6m'
declare -r CLR_REVERSE='\033[7m'
declare -r CLR_HIDDEN='\033[8m'
declare -r CLR_STRIKE='\033[9m'
declare -r CLR_DEFAULT_FONT='\033[10m'
declare -r CLR_ALT_FONT_1='\033[11m'
declare -r CLR_ALT_FONT_2='\033[12m'
declare -r CLR_ALT_FONT_3='\033[13m'
declare -r CLR_ALT_FONT_4='\033[14m'
declare -r CLR_ALT_FONT_5='\033[15m'
declare -r CLR_ALT_FONT_6='\033[16m'
declare -r CLR_ALT_FONT_7='\033[17m'
declare -r CLR_ALT_FONT_8='\033[18m'
declare -r CLR_ALT_FONT_9='\033[19m'
declare -r CLR_FRAKTUR='\033[20m'
declare -r CLR_DOUBLE_UNDERLINE='\033[21m'
declare -r CLR_NORMAL='\033[22m'
declare -r CLR_NOT_ITALIC='\033[23m'
declare -r CLR_NOT_UNDERLINE='\033[24m'
declare -r CLR_NOT_BLINK='\033[25m'
declare -r CLR_PROPORTIONAL='\033[26m'
declare -r CLR_NOT_REVERSE='\033[27m'
declare -r CLR_REVEAL='\033[28m'
declare -r CLR_NOT_STRIKE='\033[29m'

# Standard Foreground Colors (30-37)
declare -r CLR_FG_BLACK='\033[30m'
declare -r CLR_FG_RED='\033[31m'
declare -r CLR_FG_GREEN='\033[32m'
declare -r CLR_FG_YELLOW='\033[33m'
declare -r CLR_FG_BLUE='\033[34m'
declare -r CLR_FG_MAGENTA='\033[35m'
declare -r CLR_FG_CYAN='\033[36m'
declare -r CLR_FG_WHITE='\033[37m'
declare -r CLR_FG_DEFAULT='\033[39m'

# Standard Background Colors (40-47)
declare -r CLR_BG_BLACK='\033[40m'
declare -r CLR_BG_RED='\033[41m'
declare -r CLR_BG_GREEN='\033[42m'
declare -r CLR_BG_YELLOW='\033[43m'
declare -r CLR_BG_BLUE='\033[44m'
declare -r CLR_BG_MAGENTA='\033[45m'
declare -r CLR_BG_CYAN='\033[46m'
declare -r CLR_BG_WHITE='\033[47m'
declare -r CLR_BG_DEFAULT='\033[49m'

# Bright Foreground Colors (90-97)
declare -r CLR_FG_BRIGHT_BLACK='\033[90m'
declare -r CLR_FG_BRIGHT_RED='\033[91m'
declare -r CLR_FG_BRIGHT_GREEN='\033[92m'
declare -r CLR_FG_BRIGHT_YELLOW='\033[93m'
declare -r CLR_FG_BRIGHT_BLUE='\033[94m'
declare -r CLR_FG_BRIGHT_MAGENTA='\033[95m'
declare -r CLR_FG_BRIGHT_CYAN='\033[96m'
declare -r CLR_FG_BRIGHT_WHITE='\033[97m'

# Bright Background Colors (100-107)
declare -r CLR_BG_BRIGHT_BLACK='\033[100m'
declare -r CLR_BG_BRIGHT_RED='\033[101m'
declare -r CLR_BG_BRIGHT_GREEN='\033[102m'
declare -r CLR_BG_BRIGHT_YELLOW='\033[103m'
declare -r CLR_BG_BRIGHT_BLUE='\033[104m'
declare -r CLR_BG_BRIGHT_MAGENTA='\033[105m'
declare -r CLR_BG_BRIGHT_CYAN='\033[106m'
declare -r CLR_BG_BRIGHT_WHITE='\033[107m'

# ==============================================================================
# MODULE 2.2: 256-COLOR PALETTE
# ==============================================================================

# Standard Colors (0-15)
declare -r CLR256_BLACK='\033[38;5;0m'
declare -r CLR256_MAROON='\033[38;5;1m'
declare -r CLR256_GREEN='\033[38;5;2m'
declare -r CLR256_OLIVE='\033[38;5;3m'
declare -r CLR256_NAVY='\033[38;5;4m'
declare -r CLR256_PURPLE='\033[38;5;5m'
declare -r CLR256_TEAL='\033[38;5;6m'
declare -r CLR256_SILVER='\033[38;5;7m'
declare -r CLR256_GRAY='\033[38;5;8m'
declare -r CLR256_RED='\033[38;5;9m'
declare -r CLR256_LIME='\033[38;5;10m'
declare -r CLR256_YELLOW='\033[38;5;11m'
declare -r CLR256_BLUE='\033[38;5;12m'
declare -r CLR256_FUCHSIA='\033[38;5;13m'
declare -r CLR256_AQUA='\033[38;5;14m'
declare -r CLR256_WHITE='\033[38;5;15m'

# Extended 256-Color Palette (Selected Colors)
declare -r CLR256_DARK_RED='\033[38;5;52m'
declare -r CLR256_DARK_GREEN='\033[38;5;22m'
declare -r CLR256_DARK_YELLOW='\033[38;5;58m'
declare -r CLR256_DARK_BLUE='\033[38;5;17m'
declare -r CLR256_DARK_MAGENTA='\033[38;5;53m'
declare -r CLR256_DARK_CYAN='\033[38;5;23m'
declare -r CLR256_LIGHT_RED='\033[38;5;203m'
declare -r CLR256_LIGHT_GREEN='\033[38;5;119m'
declare -r CLR256_LIGHT_YELLOW='\033[38;5;227m'
declare -r CLR256_LIGHT_BLUE='\033[38;5;117m'
declare -r CLR256_LIGHT_MAGENTA='\033[38;5;213m'
declare -r CLR256_LIGHT_CYAN='\033[38;5;159m'
declare -r CLR256_ORANGE='\033[38;5;208m'
declare -r CLR256_PINK='\033[38;5;213m'
declare -r CLR256_CORAL='\033[38;5;209m'
declare -r CLR256_GOLD='\033[38;5;220m'
declare -r CLR256_BRONZE='\033[38;5;166m'
declare -r CLR256_CRIMSON='\033[38;5;196m'
declare -r CLR256_EMERALD='\033[38;5;46m'
declare -r CLR256_SAPPHIRE='\033[38;5;39m'

# Grayscale (232-255)
declare -r CLR256_GRAY_1='\033[38;5;232m'
declare -r CLR256_GRAY_2='\033[38;5;233m'
declare -r CLR256_GRAY_3='\033[38;5;234m'
declare -r CLR256_GRAY_4='\033[38;5;235m'
declare -r CLR256_GRAY_5='\033[38;5;236m'
declare -r CLR256_GRAY_6='\033[38;5;237m'
declare -r CLR256_GRAY_7='\033[38;5;238m'
declare -r CLR256_GRAY_8='\033[38;5;239m'
declare -r CLR256_GRAY_9='\033[38;5;240m'
declare -r CLR256_GRAY_10='\033[38;5;241m'
declare -r CLR256_GRAY_11='\033[38;5;242m'
declare -r CLR256_GRAY_12='\033[38;5;243m'
declare -r CLR256_GRAY_13='\033[38;5;244m'
declare -r CLR256_GRAY_14='\033[38;5;245m'
declare -r CLR256_GRAY_15='\033[38;5;246m'
declare -r CLR256_GRAY_16='\033[38;5;247m'
declare -r CLR256_GRAY_17='\033[38;5;248m'
declare -r CLR256_GRAY_18='\033[38;5;249m'
declare -r CLR256_GRAY_19='\033[38;5;250m'
declare -r CLR256_GRAY_20='\033[38;5;251m'
declare -r CLR256_GRAY_21='\033[38;5;252m'
declare -r CLR256_GRAY_22='\033[38;5;253m'
declare -r CLR256_GRAY_23='\033[38;5;254m'
declare -r CLR256_GRAY_24='\033[38;5;255m'

# 256-Color Backgrounds
declare -r CLR256_BG_DARK='\033[48;5;232m'
declare -r CLR256_BG_DARK_GRAY='\033[48;5;236m'
declare -r CLR256_BG_MEDIUM_GRAY='\033[48;5;240m'
declare -r CLR256_BG_LIGHT_GRAY='\033[48;5;250m'
declare -r CLR256_BG_RED='\033[48;5;52m'
declare -r CLR256_BG_GREEN='\033[48;5;22m'
declare -r CLR256_BG_BLUE='\033[48;5;17m'
declare -r CLR256_BG_YELLOW='\033[48;5;58m'
declare -r CLR256_BG_ORANGE='\033[48;5;94m'
declare -r CLR256_BG_PURPLE='\033[48;5;53m'

# ==============================================================================
# MODULE 2.3: TRUE COLOR (24-BIT) SUPPORT
# ==============================================================================

# True Color Foreground - Primary Colors
declare -r CLRTC_RED='\033[38;2;255;0;0m'
declare -r CLRTC_GREEN='\033[38;2;0;255;0m'
declare -r CLRTC_BLUE='\033[38;2;0;0;255m'
declare -r CLRTC_YELLOW='\033[38;2;255;255;0m'
declare -r CLRTC_CYAN='\033[38;2;0;255;255m'
declare -r CLRTC_MAGENTA='\033[38;2;255;0;255m'
declare -r CLRTC_WHITE='\033[38;2;255;255;255m'
declare -r CLRTC_BLACK='\033[38;2;0;0;0m'

# True Color - Extended Palette
declare -r CLRTC_ORANGE='\033[38;2;255;165;0m'
declare -r CLRTC_PINK='\033[38;2;255;192;203m'
declare -r CLRTC_PURPLE='\033[38;2;128;0;128m'
declare -r CLRTC_LIME='\033[38;2;50;205;50m'
declare -r CLRTC_TEAL='\033[38;2;0;128;128m'
declare -r CLRTC_GOLD='\033[38;2;255;215;0m'
declare -r CLRTC_SILVER='\033[38;2;192;192;192m'
declare -r CLRTC_CORAL='\033[38;2;255;127;80m'
declare -r CLRTC_SALMON='\033[38;2;250;128;114m'
declare -r CLRTC_CRIMSON='\033[38;2;220;20;60m'
declare -r CLRTC_MAROON='\033[38;2;128;0;0m'
declare -r CLRTC_OLIVE='\033[38;2;128;128;0m'
declare -r CLRTC_NAVY='\033[38;2;0;0;128m'
declare -r CLRTC_AQUA='\033[38;2;0;255;255m'
declare -r CLRTC_INDIGO='\033[38;2;75;0;130m'
declare -r CLRTC_VIOLET='\033[38;2;238;130;238m'
declare -r CLRTC_TURQUOISE='\033[38;2;64;224;208m'
declare -r CLRTC_CHOCOLATE='\033[38;2;210;105;30m'
declare -r CLRTC_TOMATO='\033[38;2;255;99;71m'
declare -r CLRTC_FOREST_GREEN='\033[38;2;34;139;34m'
declare -r CLRTC_STEEL_BLUE='\033[38;2;70;130;180m'
declare -r CLRTC_ROYAL_BLUE='\033[38;2;65;105;225m'
declare -r CLRTC_SKY_BLUE='\033[38;2;135;206;235m'
declare -r CLRTC_MIDNIGHT_BLUE='\033[38;2;25;25;112m'
declare -r CLRTC_SLATE_GRAY='\033[38;2;112;128;144m'
declare -r CLRTC_DARK_SLATE='\033[38;2;47;79;79m'
declare -r CLRTC_DIM_GRAY='\033[38;2;105;105;105m'
declare -r CLRTC_LAVENDER='\033[38;2;230;230;250m'
declare -r CLRTC_PLUM='\033[38;2;221;160;221m'
declare -r CLRTC_ORCHID='\033[38;2;218;112;214m'
declare -r CLRTC_DEEP_PINK='\033[38;2;255;20;147m'
declare -r CLRTC_HOT_PINK='\033[38;2;255;105;180m'
declare -r CLRTC_KHAKI='\033[38;2;240;230;140m'
declare -r CLRTC_WHEAT='\033[38;2;245;222;179m'
declare -r CLRTC_PEACH='\033[38;2;255;218;185m'
declare -r CLRTC_MINT='\033[38;2;189;252;201m'
declare -r CLRTC_HONEYDEW='\033[38;2;240;255;240m'
declare -r CLRTC_AZURE='\033[38;2;240;255;255m'
declare -r CLRTC_IVORY='\033[38;2;255;255;240m'
declare -r CLRTC_SNOW='\033[38;2;255;250;250m'
declare -r CLRTC_LINEN='\033[38;2;250;240;230m'
declare -r CLRTC_SEASHELL='\033[38;2;255;245;238m'
declare -r CLRTC_BEIGE='\033[38;2;245;245;220m'
declare -r CLRTC_ANTIQUE_WHITE='\033[38;2;250;235;215m'
declare -r CLRTC_BISQUE='\033[38;2;255;228;196m'
declare -r CLRTC_BLANCHED_ALMOND='\033[38;2;255;235;205m'
declare -r CLRTC_CORNSILK='\033[38;2;255;248;220m'
declare -r CLRTC_LEMON_CHIFFON='\033[38;2;255;250;205m'
declare -r CLRTC_LIGHT_GOLDENROD='\033[38;2;250;250;210m'
declare -r CLRTC_PAPAYA_WHIP='\033[38;2;255;239;213m'
declare -r CLRTC_MOCCASIN='\033[38;2;255;228;181m'
declare -r CLRTC_NAVAJO_WHITE='\033[38;2;255;222;173m'

# True Color Backgrounds
declare -r CLRTC_BG_DARK='\033[48;2;20;20;20m'
declare -r CLRTC_BG_DARKER='\033[48;2;10;10;10m'
declare -r CLRTC_BG_LIGHT='\033[48;2;240;240;240m'
declare -r CLRTC_BG_RED='\033[48;2;60;0;0m'
declare -r CLRTC_BG_GREEN='\033[48;2;0;60;0m'
declare -r CLRTC_BG_BLUE='\033[48;2;0;0;60m'
declare -r CLRTC_BG_YELLOW='\033[48;2;60;60;0m'
declare -r CLRTC_BG_PURPLE='\033[48;2;40;0;40m'
declare -r CLRTC_BG_TEAL='\033[48;2;0;40;40m'

# ==============================================================================
# MODULE 2.4: SEMANTIC COLOR ALIASES
# ==============================================================================

# Status Colors
declare -r COLOR_SUCCESS="$CLR256_EMERALD"
declare -r COLOR_ERROR="$CLR256_CRIMSON"
declare -r COLOR_WARNING="$CLR256_ORANGE"
declare -r COLOR_INFO="$CLR256_SAPPHIRE"
declare -r COLOR_DEBUG="$CLR256_GRAY_12"
declare -r COLOR_TRACE="$CLR256_GRAY_8"
declare -r COLOR_NOTICE="$CLR256_AQUA"
declare -r COLOR_CRITICAL="$CLR256_CRIMSON$CLR_BOLD"
declare -r COLOR_EMERGENCY="$CLR256_CRIMSON$CLR_BOLD$CLR_BLINK"

# Connection Status Colors
declare -r COLOR_CONNECTED="$CLR256_EMERALD"
declare -r COLOR_DISCONNECTED="$CLR256_CRIMSON"
declare -r COLOR_CONNECTING="$CLR256_YELLOW"
declare -r COLOR_ACTIVE="$CLR256_LIME"
declare -r COLOR_IDLE="$CLR256_GRAY_12"
declare -r COLOR_TIMEOUT="$CLR256_ORANGE"
declare -r COLOR_BLOCKED="$CLR256_RED"

# Network Direction Colors
declare -r COLOR_INBOUND="$CLR256_SAPPHIRE"
declare -r COLOR_OUTBOUND="$CLR256_ORANGE"
declare -r COLOR_BIDIRECTIONAL="$CLR256_PURPLE"
declare -r COLOR_EXTERNAL="$CLR256_ORANGE"
declare -r COLOR_INTERNAL="$CLR256_SAPPHIRE"
declare -r COLOR_LOCAL="$CLR256_TEAL"

# Threat Level Colors
declare -r COLOR_THREAT_NONE="$CLR256_GRAY_12"
declare -r COLOR_THREAT_LOW="$CLR256_EMERALD"
declare -r COLOR_THREAT_MEDIUM="$CLR256_YELLOW"
declare -r COLOR_THREAT_HIGH="$CLR256_ORANGE"
declare -r COLOR_THREAT_CRITICAL="$CLR256_CRIMSON"
declare -r COLOR_THREAT_UNKNOWN="$CLR256_GRAY_8"

# Protocol Colors
declare -r COLOR_PROTO_TCP="$CLR256_SAPPHIRE"
declare -r COLOR_PROTO_UDP="$CLR256_EMERALD"
declare -r COLOR_PROTO_ICMP="$CLR256_YELLOW"
declare -r COLOR_PROTO_HTTP="$CLR256_LIME"
declare -r COLOR_PROTO_HTTPS="$CLR256_EMERALD"
declare -r COLOR_PROTO_SSH="$CLR256_ORANGE"
declare -r COLOR_PROTO_FTP="$CLR256_CRIMSON"
declare -r COLOR_PROTO_DNS="$CLR256_AQUA"
declare -r COLOR_PROTO_SMTP="$CLR256_PURPLE"
declare -r COLOR_PROTO_OTHER="$CLR256_GRAY_12"

# UI Element Colors
declare -r COLOR_HEADER="$CLR256_SAPPHIRE"
declare -r COLOR_FOOTER="$CLR256_GRAY_12"
declare -r COLOR_BORDER="$CLR256_GRAY_8"
declare -r COLOR_TITLE="$CLR256_WHITE$CLR_BOLD"
declare -r COLOR_SUBTITLE="$CLR256_GRAY_16"
declare -r COLOR_LABEL="$CLR256_GRAY_14"
declare -r COLOR_VALUE="$CLR256_WHITE"
declare -r COLOR_HIGHLIGHT="$CLR256_YELLOW"
declare -r COLOR_SELECTED="$CLR256_SAPPHIRE$CLR_REVERSE"
declare -r COLOR_DISABLED="$CLR256_GRAY_8"

# Legacy Compatibility Aliases
declare -r RED='\033[38;5;196m'
declare -r GREEN='\033[38;5;46m'
declare -r BLUE='\033[38;5;39m'
declare -r YELLOW='\033[38;5;226m'
declare -r ORANGE='\033[38;5;208m'
declare -r PURPLE='\033[38;5;129m'
declare -r CYAN='\033[38;5;51m'
declare -r GRAY='\033[38;5;240m'
declare -r WHITE='\033[38;5;255m'
declare -r BG_DARK='\033[48;5;232m'
declare -r BG_HEADER='\033[48;5;236m'
declare -r NC='\033[0m'
declare -r BOLD='\033[1m'
declare -r DIM='\033[2m'


# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 3: UNICODE SYMBOLS AND ICONS                                 ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 3.1: STATUS AND INDICATOR ICONS
# ==============================================================================

# Basic Status Icons
declare -r ICON_SUCCESS="✓"
declare -r ICON_SUCCESS_FILLED="✔"
declare -r ICON_ERROR="✗"
declare -r ICON_ERROR_FILLED="✘"
declare -r ICON_WARNING="⚠"
declare -r ICON_WARNING_FILLED="⚠️"
declare -r ICON_INFO="ℹ"
declare -r ICON_INFO_FILLED="ℹ️"
declare -r ICON_QUESTION="?"
declare -r ICON_QUESTION_FILLED="❓"
declare -r ICON_EXCLAMATION="!"
declare -r ICON_EXCLAMATION_FILLED="❗"

# Loading and Progress Icons
declare -r ICON_LOADING="⟳"
declare -r ICON_LOADING_ALT="↻"
declare -r ICON_REFRESH="🔄"
declare -r ICON_SYNC="🔃"
declare -r ICON_HOURGLASS="⏳"
declare -r ICON_HOURGLASS_DONE="⌛"
declare -r ICON_CLOCK="🕐"
declare -r ICON_STOPWATCH="⏱"
declare -r ICON_TIMER="⏲"
declare -r ICON_ALARM="⏰"

# Star and Rating Icons
declare -r ICON_STAR="★"
declare -r ICON_STAR_EMPTY="☆"
declare -r ICON_STAR_HALF="⯪"
declare -r ICON_STAR_SPARKLE="✨"
declare -r ICON_HEART="❤"
declare -r ICON_HEART_EMPTY="♡"
declare -r ICON_DIAMOND="◆"
declare -r ICON_DIAMOND_EMPTY="◇"

# Arrow Icons
declare -r ICON_ARROW_RIGHT="→"
declare -r ICON_ARROW_LEFT="←"
declare -r ICON_ARROW_UP="↑"
declare -r ICON_ARROW_DOWN="↓"
declare -r ICON_ARROW_UP_RIGHT="↗"
declare -r ICON_ARROW_UP_LEFT="↖"
declare -r ICON_ARROW_DOWN_RIGHT="↘"
declare -r ICON_ARROW_DOWN_LEFT="↙"
declare -r ICON_ARROW_LEFT_RIGHT="↔"
declare -r ICON_ARROW_UP_DOWN="↕"
declare -r ICON_DOUBLE_ARROW_RIGHT="⇒"
declare -r ICON_DOUBLE_ARROW_LEFT="⇐"
declare -r ICON_DOUBLE_ARROW_UP="⇑"
declare -r ICON_DOUBLE_ARROW_DOWN="⇓"
declare -r ICON_TRIPLE_ARROW_RIGHT="⇶"
declare -r ICON_CURVED_ARROW_RIGHT="↪"
declare -r ICON_CURVED_ARROW_LEFT="↩"
declare -r ICON_CIRCLED_ARROW_RIGHT="➡"
declare -r ICON_CIRCLED_ARROW_LEFT="⬅"
declare -r ICON_CIRCLED_ARROW_UP="⬆"
declare -r ICON_CIRCLED_ARROW_DOWN="⬇"

# ==============================================================================
# MODULE 3.2: CONNECTION AND NETWORK ICONS
# ==============================================================================

# Connection State Icons
declare -r ICON_CONNECTED="◉"
declare -r ICON_DISCONNECTED="○"
declare -r ICON_CONNECTING="◐"
declare -r ICON_ACTIVE="●"
declare -r ICON_INACTIVE="◌"
declare -r ICON_ONLINE="🟢"
declare -r ICON_OFFLINE="🔴"
declare -r ICON_IDLE="🟡"
declare -r ICON_BUSY="🟠"

# Data Transfer Icons
declare -r ICON_TRANSMIT="⬆"
declare -r ICON_RECEIVE="⬇"
declare -r ICON_BIDIRECTIONAL="⬍"
declare -r ICON_UPLOAD="📤"
declare -r ICON_DOWNLOAD="📥"
declare -r ICON_SYNC_UPLOAD="🔼"
declare -r ICON_SYNC_DOWNLOAD="🔽"

# Network Device Icons
declare -r ICON_NETWORK="🌐"
declare -r ICON_GLOBE="🌍"
declare -r ICON_WORLD="🌎"
declare -r ICON_EARTH="🌏"
declare -r ICON_COMPUTER="💻"
declare -r ICON_DESKTOP="🖥"
declare -r ICON_LAPTOP="💻"
declare -r ICON_SERVER="🖥"
declare -r ICON_DATABASE="🗄"
declare -r ICON_ROUTER="📡"
declare -r ICON_SWITCH="🔀"
declare -r ICON_HUB="⚙"
declare -r ICON_MODEM="📶"
declare -r ICON_ANTENNA="📡"
declare -r ICON_SATELLITE="🛰"
declare -r ICON_CABLE="🔌"
declare -r ICON_ETHERNET="🔗"
declare -r ICON_USB="🔌"
declare -r ICON_PHONE="📱"
declare -r ICON_TABLET="📱"
declare -r ICON_PRINTER="🖨"
declare -r ICON_CAMERA="📷"
declare -r ICON_WEBCAM="📹"
declare -r ICON_MICROPHONE="🎤"
declare -r ICON_SPEAKER="🔊"
declare -r ICON_HEADPHONES="🎧"

# Security Icons
declare -r ICON_FIREWALL="🔥"
declare -r ICON_SHIELD="🛡"
declare -r ICON_SHIELD_CHECK="✅🛡"
declare -r ICON_LOCK="🔒"
declare -r ICON_UNLOCK="🔓"
declare -r ICON_KEY="🔑"
declare -r ICON_KEYS="🗝"
declare -r ICON_PASSWORD="🔐"
declare -r ICON_ENCRYPTED="🔏"
declare -r ICON_CERTIFICATE="📜"
declare -r ICON_FINGERPRINT="👆"
declare -r ICON_EYE="👁"
declare -r ICON_HIDDEN="🙈"
declare -r ICON_GUARD="💂"
declare -r ICON_POLICE="🚔"
declare -r ICON_DETECTIVE="🕵"

# Alert and Warning Icons
declare -r ICON_ALERT="🚨"
declare -r ICON_SIREN="🚨"
declare -r ICON_DANGER="⚡"
declare -r ICON_HAZARD="☢"
declare -r ICON_BIOHAZARD="☣"
declare -r ICON_TOXIC="☠"
declare -r ICON_SKULL="💀"
declare -r ICON_CROSSBONES="☠"
declare -r ICON_BUG="🐛"
declare -r ICON_BEETLE="🪲"
declare -r ICON_ANT="🐜"
declare -r ICON_SPIDER="🕷"
declare -r ICON_WEB="🕸"
declare -r ICON_BOMB="💣"
declare -r ICON_EXPLOSION="💥"
declare -r ICON_FIRE="🔥"
declare -r ICON_FLAME="🔥"
declare -r ICON_VIRUS="🦠"
declare -r ICON_MICROBE="🦠"
declare -r ICON_BACTERIA="🦠"
declare -r ICON_TROJAN="🐴"
declare -r ICON_WORM="🪱"
declare -r ICON_MALWARE="👾"
declare -r ICON_HACKER="🧑‍💻"
declare -r ICON_NINJA="🥷"
declare -r ICON_GHOST="👻"
declare -r ICON_ALIEN="👽"
declare -r ICON_ROBOT="🤖"
declare -r ICON_PIRATE="🏴‍☠️"

# ==============================================================================
# MODULE 3.3: FILE AND DATA ICONS
# ==============================================================================

# File Type Icons
declare -r ICON_FILE="📄"
declare -r ICON_FILE_BLANK="📃"
declare -r ICON_FILE_TEXT="📝"
declare -r ICON_FILE_CODE="📜"
declare -r ICON_FILE_CONFIG="⚙"
declare -r ICON_FILE_IMAGE="🖼"
declare -r ICON_FILE_AUDIO="🎵"
declare -r ICON_FILE_VIDEO="🎬"
declare -r ICON_FILE_ARCHIVE="📦"
declare -r ICON_FILE_BINARY="💾"
declare -r ICON_FILE_PDF="📕"
declare -r ICON_FILE_WORD="📘"
declare -r ICON_FILE_EXCEL="📗"
declare -r ICON_FILE_POWERPOINT="📙"
declare -r ICON_FILE_DATABASE="🗃"
declare -r ICON_FILE_LOG="📋"

# Folder Icons
declare -r ICON_FOLDER="📁"
declare -r ICON_FOLDER_OPEN="📂"
declare -r ICON_FOLDER_LOCKED="🔒📁"
declare -r ICON_FOLDER_SHARED="📁🔗"
declare -r ICON_FOLDER_HOME="🏠"
declare -r ICON_FOLDER_DOWNLOAD="📥"
declare -r ICON_FOLDER_UPLOAD="📤"
declare -r ICON_FOLDER_TRASH="🗑"

# Data Icons
declare -r ICON_CHART="📊"
declare -r ICON_CHART_BAR="📊"
declare -r ICON_CHART_LINE="📈"
declare -r ICON_CHART_DOWN="📉"
declare -r ICON_CHART_PIE="🥧"
declare -r ICON_TABLE="📋"
declare -r ICON_LIST="📝"
declare -r ICON_GRID="🔲"
declare -r ICON_CALENDAR="📅"
declare -r ICON_CLIPBOARD="📋"
declare -r ICON_NOTEBOOK="📓"
declare -r ICON_BOOK="📕"
declare -r ICON_BOOKS="📚"
declare -r ICON_BOOKMARK="🔖"
declare -r ICON_TAG="🏷"
declare -r ICON_TAGS="🏷"
declare -r ICON_LABEL="🏷"

# ==============================================================================
# MODULE 3.4: SPINNER AND PROGRESS CHARACTERS
# ==============================================================================

# Spinner Character Arrays
declare -a SPINNER_BRAILLE=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
declare -a SPINNER_DOTS=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
declare -a SPINNER_LINE=('|' '/' '-' '\\')
declare -a SPINNER_GROW=('.' 'o' 'O' '@' '*' ' ')
declare -a SPINNER_BOUNCE=('⠁' '⠂' '⠄' '⠂')
declare -a SPINNER_ARC=('◜' '◠' '◝' '◞' '◡' '◟')
declare -a SPINNER_CIRCLE=('◐' '◓' '◑' '◒')
declare -a SPINNER_SQUARE=('◰' '◳' '◲' '◱')
declare -a SPINNER_CLOCK=('🕐' '🕑' '🕒' '🕓' '🕔' '🕕' '🕖' '🕗' '🕘' '🕙' '🕚' '🕛')
declare -a SPINNER_MOON=('🌑' '🌒' '🌓' '🌔' '🌕' '🌖' '🌗' '🌘')
declare -a SPINNER_EARTH=('🌍' '🌎' '🌏')
declare -a SPINNER_ARROWS=('←' '↖' '↑' '↗' '→' '↘' '↓' '↙')
declare -a SPINNER_TRIANGLE=('◢' '◣' '◤' '◥')
declare -a SPINNER_PONG=('▐' '▐' '▐' '▐' '▐' '▐' '▐' '▐')
declare -a SPINNER_PULSE=('█' '▓' '▒' '░' '▒' '▓')
declare -a SPINNER_GROWING=('▁' '▂' '▃' '▄' '▅' '▆' '▇' '█' '▇' '▆' '▅' '▄' '▃' '▂')
declare -a SPINNER_FLIP=('_' '_' '_' '-' '`' '`' "'" '´' '-' '_' '_' '_')

# Progress Bar Characters
declare -r PROGRESS_FILLED="█"
declare -r PROGRESS_EMPTY="░"
declare -r PROGRESS_PARTIAL_1="▏"
declare -r PROGRESS_PARTIAL_2="▎"
declare -r PROGRESS_PARTIAL_3="▍"
declare -r PROGRESS_PARTIAL_4="▌"
declare -r PROGRESS_PARTIAL_5="▋"
declare -r PROGRESS_PARTIAL_6="▊"
declare -r PROGRESS_PARTIAL_7="▉"
declare -r PROGRESS_SHADED_LIGHT="░"
declare -r PROGRESS_SHADED_MEDIUM="▒"
declare -r PROGRESS_SHADED_DARK="▓"
declare -r PROGRESS_BLOCK="■"
declare -r PROGRESS_CIRCLE_FILLED="●"
declare -r PROGRESS_CIRCLE_EMPTY="○"
declare -r PROGRESS_DIAMOND_FILLED="◆"
declare -r PROGRESS_DIAMOND_EMPTY="◇"
declare -r PROGRESS_START="["
declare -r PROGRESS_END="]"
declare -r PROGRESS_START_ROUND="("
declare -r PROGRESS_END_ROUND=")"
declare -r PROGRESS_START_ANGLE="<"
declare -r PROGRESS_END_ANGLE=">"
declare -r PROGRESS_START_CURLY="{"
declare -r PROGRESS_END_CURLY="}"

# ==============================================================================
# MODULE 3.5: BOX DRAWING CHARACTERS
# ==============================================================================

# Single Line Box Drawing
declare -r BOX_H="─"
declare -r BOX_V="│"
declare -r BOX_TL="┌"
declare -r BOX_TR="┐"
declare -r BOX_BL="└"
declare -r BOX_BR="┘"
declare -r BOX_T_DOWN="┬"
declare -r BOX_T_UP="┴"
declare -r BOX_T_RIGHT="├"
declare -r BOX_T_LEFT="┤"
declare -r BOX_CROSS="┼"

# Double Line Box Drawing
declare -r BOX_DH="═"
declare -r BOX_DV="║"
declare -r BOX_DTL="╔"
declare -r BOX_DTR="╗"
declare -r BOX_DBL="╚"
declare -r BOX_DBR="╝"
declare -r BOX_DT_DOWN="╦"
declare -r BOX_DT_UP="╩"
declare -r BOX_DT_RIGHT="╠"
declare -r BOX_DT_LEFT="╣"
declare -r BOX_DCROSS="╬"

# Mixed Line Box Drawing (Double Horizontal, Single Vertical)
declare -r BOX_MH_TL="╒"
declare -r BOX_MH_TR="╕"
declare -r BOX_MH_BL="╘"
declare -r BOX_MH_BR="╛"
declare -r BOX_MH_T_DOWN="╤"
declare -r BOX_MH_T_UP="╧"
declare -r BOX_MH_T_RIGHT="╞"
declare -r BOX_MH_T_LEFT="╡"
declare -r BOX_MH_CROSS="╪"

# Mixed Line Box Drawing (Single Horizontal, Double Vertical)
declare -r BOX_MV_TL="╓"
declare -r BOX_MV_TR="╖"
declare -r BOX_MV_BL="╙"
declare -r BOX_MV_BR="╜"
declare -r BOX_MV_T_DOWN="╥"
declare -r BOX_MV_T_UP="╨"
declare -r BOX_MV_T_RIGHT="╟"
declare -r BOX_MV_T_LEFT="╢"
declare -r BOX_MV_CROSS="╫"

# Rounded Box Drawing
declare -r BOX_RTL="╭"
declare -r BOX_RTR="╮"
declare -r BOX_RBL="╰"
declare -r BOX_RBR="╯"

# Heavy Box Drawing
declare -r BOX_HH="━"
declare -r BOX_HV="┃"
declare -r BOX_HTL="┏"
declare -r BOX_HTR="┓"
declare -r BOX_HBL="┗"
declare -r BOX_HBR="┛"
declare -r BOX_HT_DOWN="┳"
declare -r BOX_HT_UP="┻"
declare -r BOX_HT_RIGHT="┣"
declare -r BOX_HT_LEFT="┫"
declare -r BOX_HCROSS="╋"

# Dashed Box Drawing
declare -r BOX_DASH_H2="╌"
declare -r BOX_DASH_H3="┄"
declare -r BOX_DASH_H4="┈"
declare -r BOX_DASH_V2="╎"
declare -r BOX_DASH_V3="┆"
declare -r BOX_DASH_V4="┊"
declare -r BOX_DASH_HH2="╍"
declare -r BOX_DASH_HH3="┅"
declare -r BOX_DASH_HH4="┉"
declare -r BOX_DASH_HV2="╏"
declare -r BOX_DASH_HV3="┇"
declare -r BOX_DASH_HV4="┋"

# ==============================================================================
# MODULE 3.6: COUNTRY FLAG EMOJIS
# ==============================================================================

declare -A COUNTRY_FLAGS=(
    # Americas
    ["US"]="🇺🇸" ["CA"]="🇨🇦" ["MX"]="🇲🇽" ["BR"]="🇧🇷" ["AR"]="🇦🇷"
    ["CL"]="🇨🇱" ["CO"]="🇨🇴" ["PE"]="🇵🇪" ["VE"]="🇻🇪" ["EC"]="🇪🇨"
    ["UY"]="🇺🇾" ["PY"]="🇵🇾" ["BO"]="🇧🇴" ["GY"]="🇬🇾" ["SR"]="🇸🇷"
    ["CU"]="🇨🇺" ["DO"]="🇩🇴" ["HT"]="🇭🇹" ["JM"]="🇯🇲" ["PR"]="🇵🇷"
    ["TT"]="🇹🇹" ["BB"]="🇧🇧" ["BS"]="🇧🇸" ["CR"]="🇨🇷" ["PA"]="🇵🇦"
    ["GT"]="🇬🇹" ["HN"]="🇭🇳" ["SV"]="🇸🇻" ["NI"]="🇳🇮" ["BZ"]="🇧🇿"
    
    # Europe
    ["GB"]="🇬🇧" ["DE"]="🇩🇪" ["FR"]="🇫🇷" ["IT"]="🇮🇹" ["ES"]="🇪🇸"
    ["PT"]="🇵🇹" ["NL"]="🇳🇱" ["BE"]="🇧🇪" ["AT"]="🇦🇹" ["CH"]="🇨🇭"
    ["SE"]="🇸🇪" ["NO"]="🇳🇴" ["DK"]="🇩🇰" ["FI"]="🇫🇮" ["IS"]="🇮🇸"
    ["IE"]="🇮🇪" ["PL"]="🇵🇱" ["CZ"]="🇨🇿" ["SK"]="🇸🇰" ["HU"]="🇭🇺"
    ["RO"]="🇷🇴" ["BG"]="🇧🇬" ["GR"]="🇬🇷" ["HR"]="🇭🇷" ["SI"]="🇸🇮"
    ["RS"]="🇷🇸" ["BA"]="🇧🇦" ["MK"]="🇲🇰" ["ME"]="🇲🇪" ["AL"]="🇦🇱"
    ["LT"]="🇱🇹" ["LV"]="🇱🇻" ["EE"]="🇪🇪" ["BY"]="🇧🇾" ["UA"]="🇺🇦"
    ["MD"]="🇲🇩" ["RU"]="🇷🇺" ["LU"]="🇱🇺" ["MT"]="🇲🇹" ["CY"]="🇨🇾"
    
    # Asia
    ["CN"]="🇨🇳" ["JP"]="🇯🇵" ["KR"]="🇰🇷" ["KP"]="🇰🇵" ["IN"]="🇮🇳"
    ["PK"]="🇵🇰" ["BD"]="🇧🇩" ["LK"]="🇱🇰" ["NP"]="🇳🇵" ["BT"]="🇧🇹"
    ["MM"]="🇲🇲" ["TH"]="🇹🇭" ["VN"]="🇻🇳" ["LA"]="🇱🇦" ["KH"]="🇰🇭"
    ["MY"]="🇲🇾" ["SG"]="🇸🇬" ["ID"]="🇮🇩" ["PH"]="🇵🇭" ["TW"]="🇹🇼"
    ["HK"]="🇭🇰" ["MO"]="🇲🇴" ["MN"]="🇲🇳" ["KZ"]="🇰🇿" ["UZ"]="🇺🇿"
    ["TM"]="🇹🇲" ["TJ"]="🇹🇯" ["KG"]="🇰🇬" ["AF"]="🇦🇫" ["IR"]="🇮🇷"
    ["IQ"]="🇮🇶" ["SY"]="🇸🇾" ["JO"]="🇯🇴" ["LB"]="🇱🇧" ["IL"]="🇮🇱"
    ["PS"]="🇵🇸" ["SA"]="🇸🇦" ["AE"]="🇦🇪" ["QA"]="🇶🇦" ["KW"]="🇰🇼"
    ["BH"]="🇧🇭" ["OM"]="🇴🇲" ["YE"]="🇾🇪" ["TR"]="🇹🇷" ["AZ"]="🇦🇿"
    ["GE"]="🇬🇪" ["AM"]="🇦🇲"
    
    # Africa
    ["EG"]="🇪🇬" ["ZA"]="🇿🇦" ["NG"]="🇳🇬" ["KE"]="🇰🇪" ["ET"]="🇪🇹"
    ["GH"]="🇬🇭" ["TZ"]="🇹🇿" ["UG"]="🇺🇬" ["DZ"]="🇩🇿" ["MA"]="🇲🇦"
    ["TN"]="🇹🇳" ["LY"]="🇱🇾" ["SD"]="🇸🇩" ["SS"]="🇸🇸" ["SN"]="🇸🇳"
    ["ML"]="🇲🇱" ["NE"]="🇳🇪" ["TD"]="🇹🇩" ["CM"]="🇨🇲" ["CI"]="🇨🇮"
    ["ZW"]="🇿🇼" ["ZM"]="🇿🇲" ["MW"]="🇲🇼" ["MZ"]="🇲🇿" ["AO"]="🇦🇴"
    ["BW"]="🇧🇼" ["NA"]="🇳🇦" ["RW"]="🇷🇼" ["BI"]="🇧🇮" ["SO"]="🇸🇴"
    ["MG"]="🇲🇬" ["MU"]="🇲🇺" ["SC"]="🇸🇨" ["RE"]="🇷🇪"
    
    # Oceania
    ["AU"]="🇦🇺" ["NZ"]="🇳🇿" ["FJ"]="🇫🇯" ["PG"]="🇵🇬" ["SB"]="🇸🇧"
    ["VU"]="🇻🇺" ["NC"]="��🇨" ["WS"]="🇼🇸" ["TO"]="🇹🇴" ["GU"]="🇬🇺"
    ["PF"]="🇵🇫" ["AS"]="🇦🇸" ["CK"]="🇨🇰" ["NU"]="🇳🇺" ["TK"]="🇹🇰"
    
    # Special
    ["UNK"]="🏳️" ["UNKNOWN"]="🏳️" ["N/A"]="🏳️" ["XX"]="🏳️"
    ["EU"]="🇪🇺" ["UN"]="🇺🇳" [""]="🏳️"
)

# ==============================================================================
# MODULE 3.7: PROTOCOL AND SERVICE ICONS
# ==============================================================================

declare -A PROTOCOL_ICONS=(
    ["TCP"]="📡" ["UDP"]="📢" ["ICMP"]="📨" ["IP"]="🌐"
    ["HTTP"]="🌍" ["HTTPS"]="🔒" ["FTP"]="📁" ["FTPS"]="🔐"
    ["SSH"]="🔑" ["TELNET"]="📟" ["SMTP"]="📧" ["POP3"]="📬"
    ["IMAP"]="📪" ["DNS"]="🔍" ["DHCP"]="📋" ["NTP"]="⏰"
    ["SNMP"]="📊" ["LDAP"]="📖" ["SMB"]="💾" ["RDP"]="🖥"
    ["VNC"]="👁" ["MYSQL"]="🐬" ["PGSQL"]="🐘" ["REDIS"]="🔴"
    ["MONGODB"]="🍃" ["ELASTICSEARCH"]="🔎" ["KAFKA"]="📨"
    ["RABBITMQ"]="🐰" ["WEBSOCKET"]="🔌" ["GRPC"]="⚡"
    ["MQTT"]="📡" ["AMQP"]="📩" ["RTSP"]="📹" ["SIP"]="📞"
    ["OTHER"]="❓" ["UNKNOWN"]="❓"
)


# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 4: COMPREHENSIVE PORT DATABASE                               ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 4.1: WELL-KNOWN PORTS (0-1023)
# ==============================================================================

# Port Database: Port -> "ServiceName|Description|Risk|Protocol"
declare -A PORT_DATABASE=(
    # System Ports (0-99)
    [0]="Reserved|Reserved Port|LOW|TCP/UDP"
    [1]="TCPMUX|TCP Port Service Multiplexer|LOW|TCP"
    [5]="RJE|Remote Job Entry|MEDIUM|TCP"
    [7]="ECHO|Echo Protocol|LOW|TCP/UDP"
    [9]="DISCARD|Discard Protocol|LOW|TCP/UDP"
    [11]="SYSTAT|Active Users|MEDIUM|TCP"
    [13]="DAYTIME|Daytime Protocol|LOW|TCP/UDP"
    [17]="QOTD|Quote of the Day|LOW|TCP/UDP"
    [18]="MSP|Message Send Protocol|LOW|TCP"
    [19]="CHARGEN|Character Generator|LOW|TCP/UDP"
    [20]="FTP-DATA|FTP Data Transfer|HIGH|TCP"
    [21]="FTP|File Transfer Protocol Control|CRITICAL|TCP"
    [22]="SSH|Secure Shell|HIGH|TCP"
    [23]="TELNET|Telnet|CRITICAL|TCP"
    [25]="SMTP|Simple Mail Transfer Protocol|HIGH|TCP"
    [37]="TIME|Time Protocol|LOW|TCP/UDP"
    [42]="NAMESERVER|Host Name Server|LOW|TCP"
    [43]="WHOIS|WHOIS Protocol|LOW|TCP"
    [49]="TACACS|Login Host Protocol|HIGH|TCP/UDP"
    [53]="DNS|Domain Name System|MEDIUM|TCP/UDP"
    [67]="BOOTPS|DHCP Server|MEDIUM|UDP"
    [68]="BOOTPC|DHCP Client|LOW|UDP"
    [69]="TFTP|Trivial File Transfer Protocol|HIGH|UDP"
    [70]="GOPHER|Gopher Protocol|LOW|TCP"
    [79]="FINGER|Finger Protocol|MEDIUM|TCP"
    [80]="HTTP|Hypertext Transfer Protocol|MEDIUM|TCP"
    [88]="KERBEROS|Kerberos Authentication|HIGH|TCP/UDP"
    [95]="SUPDUP|SUPDUP Protocol|LOW|TCP"
    
    # Extended System Ports (100-199)
    [101]="HOSTNAME|NIC Host Name Server|LOW|TCP"
    [102]="ISO-TSAP|ISO-TSAP Class 0|LOW|TCP"
    [104]="ACAS|ACR/NEMA DICOM|LOW|TCP"
    [105]="CSNET-NS|CSNET Mailbox Nameserver|LOW|TCP"
    [107]="RTELNET|Remote Telnet Service|MEDIUM|TCP"
    [109]="POP2|Post Office Protocol v2|MEDIUM|TCP"
    [110]="POP3|Post Office Protocol v3|MEDIUM|TCP"
    [111]="SUNRPC|SUN Remote Procedure Call|HIGH|TCP/UDP"
    [113]="AUTH|Authentication Service|MEDIUM|TCP"
    [115]="SFTP|Simple File Transfer Protocol|MEDIUM|TCP"
    [117]="UUCP-PATH|UUCP Path Service|LOW|TCP"
    [119]="NNTP|Network News Transfer Protocol|MEDIUM|TCP"
    [123]="NTP|Network Time Protocol|LOW|UDP"
    [135]="MSRPC|Microsoft RPC|HIGH|TCP"
    [137]="NETBIOS-NS|NetBIOS Name Service|MEDIUM|UDP"
    [138]="NETBIOS-DGM|NetBIOS Datagram|MEDIUM|UDP"
    [139]="NETBIOS-SSN|NetBIOS Session|HIGH|TCP"
    [143]="IMAP|Internet Message Access Protocol|MEDIUM|TCP"
    [161]="SNMP|Simple Network Management Protocol|HIGH|UDP"
    [162]="SNMPTRAP|SNMP Trap|HIGH|UDP"
    [163]="CMIP-MAN|CMIP TCP Manager|LOW|TCP"
    [164]="CMIP-AGENT|CMIP TCP Agent|LOW|TCP"
    [174]="MAILQ|MAILQ|LOW|TCP"
    [177]="XDMCP|X Display Manager Control Protocol|MEDIUM|UDP"
    [178]="NEXTSTEP|NextStep Window Server|LOW|TCP"
    [179]="BGP|Border Gateway Protocol|MEDIUM|TCP"
    [194]="IRC|Internet Relay Chat|MEDIUM|TCP"
    [199]="SMUX|SNMP Unix Multiplexer|MEDIUM|TCP"
    
    # Extended System Ports (200-299)
    [201]="AT-RTMP|AppleTalk Routing Maintenance|LOW|UDP"
    [202]="AT-NBP|AppleTalk Name Binding|LOW|UDP"
    [204]="AT-ECHO|AppleTalk Echo|LOW|UDP"
    [206]="AT-ZIS|AppleTalk Zone Information|LOW|UDP"
    [209]="QMTP|Quick Mail Transfer Protocol|LOW|TCP"
    [210]="Z39.50|ANSI Z39.50|LOW|TCP"
    [213]="IPX|Internetwork Packet Exchange|LOW|UDP"
    [218]="MPP|Netix Message Posting Protocol|LOW|TCP"
    [220]="IMAP3|Interactive Mail Access Protocol v3|MEDIUM|TCP"
    [245]="LINK|LINK|LOW|TCP"
    [280]="HTTP-MGMT|HTTP Management|MEDIUM|TCP"
    [281]="PERSONAL-LINK|Personal Link|LOW|TCP"
    [282]="CABLEPORT-AX|Cable Port A/X|LOW|TCP"
    [286]="FXP|FXP Communication|LOW|TCP"
    [287]="K-BLOCK|K-Block|LOW|TCP"
    
    # Extended System Ports (300-399)
    [308]="NOVASTORBAKCUP|Novastor Backup|LOW|TCP"
    [311]="MAC-SERVER-ADMIN|Apple Mac OS X Server Admin|MEDIUM|TCP"
    [318]="PKIX-TIMESTAMP|PKIX TimeStamp|LOW|TCP"
    [319]="PTP-EVENT|PTP Event|LOW|UDP"
    [320]="PTP-GENERAL|PTP General|LOW|UDP"
    [323]="IMMP|Internet Message Mapping Protocol|LOW|TCP"
    [347]="FATSERV|Fatmen Server|LOW|TCP"
    [350]="MATIP-TYPE-A|MATIP Type A|LOW|TCP"
    [351]="MATIP-TYPE-B|MATIP Type B|LOW|TCP"
    [363]="RSVP_TUNNEL|RSVP Tunnel|LOW|UDP"
    [366]="ODMR|On-Demand Mail Relay|LOW|TCP"
    [369]="RPC2PORTMAP|Coda Portmapper|LOW|TCP"
    [370]="CODAAUTH2|Coda Authentication Server|LOW|TCP"
    [371]="CLEARCASE|Clearcase|LOW|TCP"
    [372]="ULISTPROC|Unix Listserv|LOW|TCP"
    [373]="LEGENT-1|Legent Corporation|LOW|TCP"
    [374]="LEGENT-2|Legent Corporation|LOW|TCP"
    [383]="HP-ALARM-MGR|HP Performance Data Alarm Manager|LOW|TCP"
    [384]="ARNS|A Remote Network Server System|LOW|TCP"
    [387]="AURP|AppleTalk Update-based Routing|LOW|TCP"
    [389]="LDAP|Lightweight Directory Access Protocol|HIGH|TCP"
    [390]="UIS|UIS|LOW|TCP"
    [391]="SYNOTICS-RELAY|SynOptics SNMP Relay Port|LOW|TCP"
    [392]="SYNOTICS-BROKER|SynOptics Port Broker Port|LOW|TCP"
    [393]="META5|Meta5|LOW|TCP"
    [394]="EMBL-NDT|EMBL Nucleic Data Transfer|LOW|TCP"
    [395]="NETCP|NETscout Control Protocol|LOW|TCP"
    [396]="NETWARE-IP|Novell Netware over IP|LOW|TCP"
    [397]="MPTN|Multi Protocol Trans Net|LOW|TCP"
    [398]="KRYPTOLAN|Kryptolan|LOW|TCP"
    [399]="ISO-TSAP-C2|ISO Transport Class 2 Non-Control|LOW|TCP"
    
    # HTTPS and Secure Services (400-499)
    [401]="UPS|Uninterruptible Power Supply|LOW|TCP"
    [402]="GENIE|Genie Protocol|LOW|TCP"
    [403]="DECAP|decap|LOW|TCP"
    [404]="NCED|nced|LOW|TCP"
    [405]="NCLD|ncld|LOW|TCP"
    [406]="IMSP|Interactive Mail Support Protocol|LOW|TCP"
    [407]="TIMBUKTU|Timbuktu|LOW|TCP"
    [408]="PRM-SM|Prospero Resource Manager Sys Man|LOW|TCP"
    [409]="PRM-NM|Prospero Resource Manager Node Man|LOW|TCP"
    [410]="DECLADEBUG|DECLadebug Remote Debug Protocol|LOW|TCP"
    [411]="RMT|Remote MT Protocol|LOW|TCP"
    [412]="SYNOPTICS-TRAP|Trap Convention Port|LOW|TCP"
    [413]="SMSP|Storage Management Services Protocol|LOW|TCP"
    [414]="INFOSEEK|InfoSeek|LOW|TCP"
    [415]="BNET|BNet|LOW|TCP"
    [416]="SILVERPLATTER|Silverplatter|LOW|TCP"
    [417]="ONMUX|Onmux|LOW|TCP"
    [418]="HYPER-G|Hyper-G|LOW|TCP"
    [419]="ARIEL1|Ariel1|LOW|TCP"
    [420]="SMPTE|SMPTE|LOW|TCP"
    [421]="ARIEL2|Ariel2|LOW|TCP"
    [422]="ARIEL3|Ariel3|LOW|TCP"
    [423]="OPC-JOB-START|IBM Operations Planning and Control Start|LOW|TCP"
    [424]="OPC-JOB-TRACK|IBM Operations Planning and Control Track|LOW|TCP"
    [425]="ICAD-EL|ICAD|LOW|TCP"
    [426]="SMARTSDP|smartsdp|LOW|TCP"
    [427]="SLP|Service Location Protocol|MEDIUM|TCP/UDP"
    [428]="OCS_CMU|OCS_CMU|LOW|TCP"
    [429]="OCS_AMU|OCS_AMU|LOW|TCP"
    [430]="UTMPSD|UTMPSD|LOW|TCP"
    [431]="UTMPCD|UTMPCD|LOW|TCP"
    [432]="IASD|IASD|LOW|TCP"
    [433]="NNSP|NNSP|LOW|TCP"
    [434]="MOBILEIP-AGENT|MobileIP-Agent|LOW|UDP"
    [435]="MOBILIP-MN|MobilIP-MN|LOW|UDP"
    [436]="DNA-CML|DNA-CML|LOW|TCP"
    [437]="COMSCM|comscm|LOW|TCP"
    [438]="DSFGW|dsfgw|LOW|TCP"
    [439]="DASP|dasp|LOW|TCP"
    [440]="SGCP|sgcp|LOW|TCP"
    [441]="DECVMS-SYSMGT|decvms-sysmgt|LOW|TCP"
    [442]="CVC_HOSTD|cvc_hostd|LOW|TCP"
    [443]="HTTPS|HTTP Secure|MEDIUM|TCP"
    [444]="SNPP|Simple Network Paging Protocol|LOW|TCP"
    [445]="MICROSOFT-DS|Microsoft Directory Services (SMB)|CRITICAL|TCP"
    [446]="DDM-RDB|DDM-Remote Relational Database Access|LOW|TCP"
    [447]="DDM-DFM|DDM-Distributed File Management|LOW|TCP"
    [448]="DDM-SSL|DDM-Remote DB Access Using Secure Sockets|LOW|TCP"
    [449]="AS-SERVERMAP|AS Server Mapper|LOW|TCP"
    [450]="TSERVER|Computer Supported Telecomy Applications|LOW|TCP"
    [451]="SFS-SMP-NET|Cray Network Semaphore Server|LOW|TCP"
    [452]="SFS-CONFIG|Cray SFS config server|LOW|TCP"
    [453]="CREATIVESERVER|CreativeServer|LOW|TCP"
    [454]="CONTENTSERVER|ContentServer|LOW|TCP"
    [455]="CREATIVEPARTNR|CreativePartnr|LOW|TCP"
    [456]="MACON-TCP|macon-tcp|LOW|TCP"
    [457]="SCOHELP|scohelp|LOW|TCP"
    [458]="APPLEQTC|Apple QuickTime|LOW|TCP"
    [459]="AMPR-RCMD|ampr-rcmd|LOW|TCP"
    [460]="SKRONK|skronk|LOW|TCP"
    [461]="DATASURFSRV|DataRampSrv|LOW|TCP"
    [462]="DATASURFSRVSEC|DataRampSrvSec|LOW|TCP"
    [463]="ALPES|alpes|LOW|TCP"
    [464]="KPASSWD|Kerberos Password|HIGH|TCP/UDP"
    [465]="SMTPS|SMTP over SSL (deprecated)|MEDIUM|TCP"
    [466]="DIGITAL-VRC|digital-vrc|LOW|TCP"
    [467]="MYLEX-MAPD|mylex-mapd|LOW|TCP"
    [468]="PHOTURIS|Photuris Session Key Management|LOW|UDP"
    [469]="RCP|Radio Control Protocol|LOW|TCP"
    [470]="SCX-PROXY|scx-proxy|LOW|TCP"
    [471]="MONDEX|Mondex|LOW|TCP"
    [472]="LJK-LOGIN|ljk-login|LOW|TCP"
    [473]="HYBRID-POP|hybrid-pop|LOW|TCP"
    [474]="TN-TL-W1|tn-tl-w1|LOW|TCP"
    [475]="TN-TL-W2|tn-tl-w2|LOW|TCP"
    [476]="TN-TL-FD1|tn-tl-fd1|LOW|TCP"
    [477]="SS7NS|ss7ns|LOW|TCP"
    [478]="SPSC|spsc|LOW|TCP"
    [479]="IAFSERVER|iafserver|LOW|TCP"
    [480]="IAFDBASE|iafdbase|LOW|TCP"
    [481]="PH|Ph service|LOW|TCP"
    [482]="BGS-NSI|bgs-nsi|LOW|TCP"
    [483]="ULPNET|ulpnet|LOW|TCP"
    [484]="INTEGRA-SME|Integra Software Management Environment|LOW|TCP"
    [485]="POWERBURST|Air Soft Power Burst|LOW|TCP"
    [486]="AVIAN|avian|LOW|TCP"
    [487]="SAFT|SAFT Simple Asynchronous File Transfer|LOW|TCP"
    [488]="GSS-HTTP|gss-http|LOW|TCP"
    [489]="NEST-PROTOCOL|nest-protocol|LOW|TCP"
    [490]="MICOM-PFS|micom-pfs|LOW|TCP"
    [491]="GO-LOGIN|go-login|LOW|TCP"
    [492]="TICF-1|Transport Independent Convergence for FNA|LOW|TCP"
    [493]="TICF-2|Transport Independent Convergence for FNA|LOW|TCP"
    [494]="POV-RAY|POV-Ray|LOW|TCP"
    [495]="INTECOURIER|intecourier|LOW|TCP"
    [496]="PIM-RP-DISC|PIM-RP-DISC|LOW|UDP"
    [497]="RETROSPECT|Retrospect backup|LOW|TCP"
    [498]="SIAM|siam|LOW|TCP"
    [499]="ISO-ILL|ISO ILL Protocol|LOW|TCP"
    [500]="ISAKMP|Internet Key Exchange (IKE)|MEDIUM|UDP"
    
    # Database and Application Ports (1000-2000)
    [1025]="NFS-OR-IIS|NFS or IIS|MEDIUM|TCP"
    [1080]="SOCKS|SOCKS Proxy|MEDIUM|TCP"
    [1194]="OPENVPN|OpenVPN|LOW|UDP"
    [1433]="MSSQL|Microsoft SQL Server|CRITICAL|TCP"
    [1434]="MSSQL-M|Microsoft SQL Server Monitor|CRITICAL|UDP"
    [1521]="ORACLE|Oracle Database|CRITICAL|TCP"
    [1723]="PPTP|Point-to-Point Tunneling Protocol|HIGH|TCP"
    [1883]="MQTT|Message Queuing Telemetry Transport|MEDIUM|TCP"
    [1900]="SSDP|Simple Service Discovery Protocol|LOW|UDP"
    [2049]="NFS|Network File System|HIGH|TCP/UDP"
    
    # Common Application Ports (2000-5000)
    [2082]="CPANEL|cPanel|MEDIUM|TCP"
    [2083]="CPANEL-SSL|cPanel SSL|MEDIUM|TCP"
    [2086]="WHM|Web Host Manager|MEDIUM|TCP"
    [2087]="WHM-SSL|Web Host Manager SSL|MEDIUM|TCP"
    [2095]="WEBMAIL|cPanel Webmail|MEDIUM|TCP"
    [2096]="WEBMAIL-SSL|cPanel Webmail SSL|MEDIUM|TCP"
    [2181]="ZOOKEEPER|Apache ZooKeeper|MEDIUM|TCP"
    [2375]="DOCKER|Docker API (unencrypted)|CRITICAL|TCP"
    [2376]="DOCKER-TLS|Docker API (TLS)|HIGH|TCP"
    [2379]="ETCD-CLIENT|etcd Client|HIGH|TCP"
    [2380]="ETCD-SERVER|etcd Server|HIGH|TCP"
    [3000]="NODEJS|Node.js (default)|MEDIUM|TCP"
    [3001]="NODEJS-ALT|Node.js Alternative|MEDIUM|TCP"
    [3128]="SQUID|Squid HTTP Proxy|MEDIUM|TCP"
    [3268]="LDAP-GC|Active Directory Global Catalog|HIGH|TCP"
    [3269]="LDAP-GC-SSL|AD Global Catalog SSL|HIGH|TCP"
    [3306]="MYSQL|MySQL Database|CRITICAL|TCP"
    [3307]="MYSQL-ALT|MySQL Alternative|CRITICAL|TCP"
    [3389]="RDP|Remote Desktop Protocol|CRITICAL|TCP"
    [3478]="STUN|Session Traversal Utilities for NAT|LOW|UDP"
    [4000]="REMOTEANYTHING|Remote Anything|HIGH|TCP"
    [4369]="EPMD|Erlang Port Mapper Daemon|MEDIUM|TCP"
    [4500]="IPSEC-NAT|IPSec NAT Traversal|MEDIUM|UDP"
    [4567]="SINATRA|Sinatra/Ruby|MEDIUM|TCP"
    [4848]="GLASSFISH|GlassFish Admin|HIGH|TCP"
    
    # Database and NoSQL (5000-7000)
    [5000]="FLASK|Python Flask/UPnP|MEDIUM|TCP"
    [5001]="FLASK-ALT|Flask Alternative|MEDIUM|TCP"
    [5432]="POSTGRESQL|PostgreSQL Database|CRITICAL|TCP"
    [5433]="POSTGRESQL-ALT|PostgreSQL Alternative|CRITICAL|TCP"
    [5500]="VNC-HTTP|VNC HTTP|HIGH|TCP"
    [5555]="ANDROID-ADB|Android Debug Bridge|CRITICAL|TCP"
    [5601]="KIBANA|Kibana Dashboard|HIGH|TCP"
    [5672]="AMQP|RabbitMQ AMQP|MEDIUM|TCP"
    [5900]="VNC|Virtual Network Computing|HIGH|TCP"
    [5901]="VNC-1|VNC Display 1|HIGH|TCP"
    [5902]="VNC-2|VNC Display 2|HIGH|TCP"
    [5903]="VNC-3|VNC Display 3|HIGH|TCP"
    [5984]="COUCHDB|Apache CouchDB|HIGH|TCP"
    [5985]="WINRM-HTTP|Windows Remote Management HTTP|HIGH|TCP"
    [5986]="WINRM-HTTPS|Windows Remote Management HTTPS|HIGH|TCP"
    [6000]="X11|X Window System|HIGH|TCP"
    [6379]="REDIS|Redis Database|CRITICAL|TCP"
    [6380]="REDIS-TLS|Redis TLS|HIGH|TCP"
    [6443]="KUBERNETES|Kubernetes API Server|CRITICAL|TCP"
    [6666]="IRC-ALT|IRC Alternative|MEDIUM|TCP"
    [6667]="IRC|Internet Relay Chat|MEDIUM|TCP"
    [6697]="IRC-SSL|IRC SSL|MEDIUM|TCP"
    
    # Web Application Ports (7000-9000)
    [7000]="CASSANDRA|Apache Cassandra|HIGH|TCP"
    [7001]="WEBLOGIC|Oracle WebLogic Server|HIGH|TCP"
    [7002]="WEBLOGIC-SSL|Oracle WebLogic Server SSL|HIGH|TCP"
    [7070]="ARCP|Real-Time Streaming Protocol|LOW|TCP"
    [7199]="CASSANDRA-JMX|Cassandra JMX|HIGH|TCP"
    [7474]="NEO4J-HTTP|Neo4j HTTP|HIGH|TCP"
    [7473]="NEO4J-HTTPS|Neo4j HTTPS|HIGH|TCP"
    [7687]="NEO4J-BOLT|Neo4j Bolt|HIGH|TCP"
    [8000]="HTTP-ALT|HTTP Alternative|MEDIUM|TCP"
    [8001]="HTTP-ALT-2|HTTP Alternative 2|MEDIUM|TCP"
    [8008]="HTTP-ALT-3|HTTP Alternative 3|MEDIUM|TCP"
    [8009]="AJP|Apache JServ Protocol|MEDIUM|TCP"
    [8080]="HTTP-PROXY|HTTP Proxy/Tomcat|MEDIUM|TCP"
    [8081]="HTTP-PROXY-ALT|HTTP Proxy Alternative|MEDIUM|TCP"
    [8082]="HTTP-ALT-4|HTTP Alternative 4|MEDIUM|TCP"
    [8083]="HTTP-ALT-5|HTTP Alternative 5|MEDIUM|TCP"
    [8084]="HTTP-ALT-6|HTTP Alternative 6|MEDIUM|TCP"
    [8085]="HTTP-ALT-7|HTTP Alternative 7|MEDIUM|TCP"
    [8086]="INFLUXDB|InfluxDB|MEDIUM|TCP"
    [8087]="RIAK|Riak Protocol Buffers|HIGH|TCP"
    [8088]="RIAK-HTTP|Riak HTTP|HIGH|TCP"
    [8089]="SPLUNK|Splunk Management|HIGH|TCP"
    [8090]="HTTP-ALT-8|HTTP Alternative 8|MEDIUM|TCP"
    [8098]="RIAK-HTTP-ALT|Riak HTTP Alternative|HIGH|TCP"
    [8161]="ACTIVEMQ|Apache ActiveMQ|HIGH|TCP"
    [8200]="VAULT|HashiCorp Vault|HIGH|TCP"
    [8300]="CONSUL|HashiCorp Consul|HIGH|TCP"
    [8301]="CONSUL-LAN|Consul LAN Gossip|HIGH|TCP"
    [8302]="CONSUL-WAN|Consul WAN Gossip|HIGH|TCP"
    [8443]="HTTPS-ALT|HTTPS Alternative|MEDIUM|TCP"
    [8444]="HTTPS-ALT-2|HTTPS Alternative 2|MEDIUM|TCP"
    [8500]="CONSUL-HTTP|Consul HTTP API|HIGH|TCP"
    [8600]="CONSUL-DNS|Consul DNS|HIGH|TCP"
    [8761]="EUREKA|Netflix Eureka|MEDIUM|TCP"
    [8888]="HTTP-ALT-9|HTTP Alternative 9|MEDIUM|TCP"
    [8983]="SOLR|Apache Solr|HIGH|TCP"
    
    # Monitoring and Analytics (9000-10000)
    [9000]="SONARQUBE|SonarQube|HIGH|TCP"
    [9001]="ETL|ETL Tools|MEDIUM|TCP"
    [9042]="CASSANDRA-CQL|Cassandra CQL Native|HIGH|TCP"
    [9043]="WEBSPHERE-ADMIN|WebSphere Admin|HIGH|TCP"
    [9060]="WEBSPHERE-ADMIN-SSL|WebSphere Admin SSL|HIGH|TCP"
    [9080]="WEBSPHERE-HTTP|WebSphere HTTP|HIGH|TCP"
    [9090]="PROMETHEUS|Prometheus Metrics|MEDIUM|TCP"
    [9091]="PROMETHEUS-PUSH|Prometheus Pushgateway|MEDIUM|TCP"
    [9092]="KAFKA|Apache Kafka|HIGH|TCP"
    [9093]="ALERTMANAGER|Prometheus Alertmanager|MEDIUM|TCP"
    [9094]="KAFKA-TLS|Apache Kafka TLS|HIGH|TCP"
    [9100]="JETDIRECT|HP JetDirect/Node Exporter|MEDIUM|TCP"
    [9160]="CASSANDRA-THRIFT|Cassandra Thrift|HIGH|TCP"
    [9200]="ELASTICSEARCH|Elasticsearch REST|CRITICAL|TCP"
    [9201]="ELASTICSEARCH-ALT|Elasticsearch Alternative|CRITICAL|TCP"
    [9300]="ELASTICSEARCH-NODE|Elasticsearch Node|CRITICAL|TCP"
    [9418]="GIT|Git Protocol|LOW|TCP"
    [9443]="HTTPS-ADMIN|HTTPS Admin|MEDIUM|TCP"
    [9999]="ABYSS|Abyss Web Server|MEDIUM|TCP"
    
    # High Ports (10000+)
    [10000]="WEBMIN|Webmin Admin|HIGH|TCP"
    [10001]="SCP-CONFIG|SCP Config|MEDIUM|TCP"
    [10050]="ZABBIX-AGENT|Zabbix Agent|MEDIUM|TCP"
    [10051]="ZABBIX-SERVER|Zabbix Server|MEDIUM|TCP"
    [10250]="KUBELET|Kubernetes Kubelet API|CRITICAL|TCP"
    [10255]="KUBELET-READONLY|Kubelet Read-only API|HIGH|TCP"
    [10256]="KUBE-PROXY|Kubernetes Kube-proxy|HIGH|TCP"
    [11211]="MEMCACHED|Memcached|CRITICAL|TCP/UDP"
    [11214]="MEMCACHED-SSL|Memcached SSL|HIGH|TCP"
    [11215]="MEMCACHED-INTERNAL|Memcached Internal|HIGH|TCP"
    [15672]="RABBITMQ-MGMT|RabbitMQ Management|HIGH|TCP"
    [17010]="MACOS-ADMIN|macOS Server Admin|MEDIUM|TCP"
    [19999]="NETDATA|Netdata Monitoring|MEDIUM|TCP"
    [25565]="MINECRAFT|Minecraft Server|LOW|TCP"
    [27015]="STEAM|Steam Game Server|LOW|UDP"
    [27017]="MONGODB|MongoDB|CRITICAL|TCP"
    [27018]="MONGODB-SHARD|MongoDB Shard|CRITICAL|TCP"
    [27019]="MONGODB-CONFIG|MongoDB Config|CRITICAL|TCP"
    [28015]="RUST|Rust Game Server|LOW|UDP"
    [28017]="MONGODB-WEB|MongoDB Web Interface|CRITICAL|TCP"
    [29015]="RUST-RCON|Rust RCON|LOW|TCP"
    [30000]="KUBERNETES-NODEPORT|Kubernetes NodePort Start|MEDIUM|TCP"
    [32767]="KUBERNETES-NODEPORT-END|Kubernetes NodePort End|MEDIUM|TCP"
    [33060]="MYSQLX|MySQL X Protocol|CRITICAL|TCP"
    [44818]="ETHERNETIP|EtherNet/IP|MEDIUM|TCP"
    [50000]="SAP|SAP Application|HIGH|TCP"
    [50070]="HADOOP-NAMENODE|Hadoop NameNode|HIGH|TCP"
    [50075]="HADOOP-DATANODE|Hadoop DataNode|HIGH|TCP"
    [50090]="HADOOP-SECONDARY|Hadoop Secondary NameNode|HIGH|TCP"
    [54321]="POSTGRESQL-ADMIN|PostgreSQL Admin|HIGH|TCP"
    [55672]="RABBITMQ-ALT|RabbitMQ Alternative|HIGH|TCP"
    [61616]="ACTIVEMQ-OPENWIRE|ActiveMQ OpenWire|HIGH|TCP"
)



# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 5: UTILITY FUNCTIONS                                         ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 5.1: LOGGING FUNCTIONS
# ==============================================================================

# Log levels
declare -r LOG_LEVEL_TRACE=0
declare -r LOG_LEVEL_DEBUG=1
declare -r LOG_LEVEL_INFO=2
declare -r LOG_LEVEL_NOTICE=3
declare -r LOG_LEVEL_WARNING=4
declare -r LOG_LEVEL_ERROR=5
declare -r LOG_LEVEL_CRITICAL=6
declare -r LOG_LEVEL_EMERGENCY=7

# Current log level
declare -g CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

# Log level names
declare -A LOG_LEVEL_NAMES=(
    [$LOG_LEVEL_TRACE]="TRACE"
    [$LOG_LEVEL_DEBUG]="DEBUG"
    [$LOG_LEVEL_INFO]="INFO"
    [$LOG_LEVEL_NOTICE]="NOTICE"
    [$LOG_LEVEL_WARNING]="WARNING"
    [$LOG_LEVEL_ERROR]="ERROR"
    [$LOG_LEVEL_CRITICAL]="CRITICAL"
    [$LOG_LEVEL_EMERGENCY]="EMERGENCY"
)

# Log level colors
declare -A LOG_LEVEL_COLORS=(
    [$LOG_LEVEL_TRACE]="$CLR256_GRAY_8"
    [$LOG_LEVEL_DEBUG]="$CLR256_GRAY_12"
    [$LOG_LEVEL_INFO]="$CLR256_SAPPHIRE"
    [$LOG_LEVEL_NOTICE]="$CLR256_AQUA"
    [$LOG_LEVEL_WARNING]="$CLR256_YELLOW"
    [$LOG_LEVEL_ERROR]="$CLR256_ORANGE"
    [$LOG_LEVEL_CRITICAL]="$CLR256_CRIMSON"
    [$LOG_LEVEL_EMERGENCY]="$CLR256_CRIMSON$CLR_BOLD$CLR_BLINK"
)

# Core logging function
_log() {
    local level="$1"
    local message="$2"
    local timestamp
    local level_name
    local level_color
    local source_info
    
    # Check if we should log at this level
    if [[ $level -lt $CURRENT_LOG_LEVEL ]]; then
        return 0
    fi
    
    # Get timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Get level name and color
    level_name="${LOG_LEVEL_NAMES[$level]:-UNKNOWN}"
    level_color="${LOG_LEVEL_COLORS[$level]:-$NC}"
    
    # Get source info (function and line number)
    source_info="${FUNCNAME[2]:-main}:${BASH_LINENO[1]:-0}"
    
    # Format log message
    local formatted_message
    if [[ $EXTIPMON_COLOR_OUTPUT -eq 1 ]]; then
        formatted_message="$CLR256_GRAY_12[$timestamp]$NC ${level_color}[$level_name]$NC $CLR256_GRAY_16[$source_info]$NC $message"
    else
        formatted_message="[$timestamp] [$level_name] [$source_info] $message"
    fi
    
    # Output to console if not quiet
    if [[ $EXTIPMON_QUIET -eq 0 ]]; then
        echo -e "$formatted_message" >&2
    fi
    
    # Output to log file if configured
    if [[ -n "${EXTIPMON_DEBUG_LOG:-}" ]] && [[ -w "${EXTIPMON_DEBUG_LOG%/*}" || -w "$EXTIPMON_DEBUG_LOG" ]]; then
        echo "[$timestamp] [$level_name] [$source_info] $message" >> "$EXTIPMON_DEBUG_LOG"
    fi
    
    # For JSON logging
    if [[ "${EXTIPMON_LOG_FORMAT:-text}" == "json" ]] && [[ -n "${EXTIPMON_EVENT_LOG:-}" ]]; then
        local json_message
        json_message=$(cat <<EOF
{"timestamp":"$timestamp","level":"$level_name","source":"$source_info","message":"$(echo "$message" | sed 's/"/\\"/g')"}
EOF
)
        echo "$json_message" >> "$EXTIPMON_EVENT_LOG"
    fi
}

# Convenience logging functions
log_trace() { _log $LOG_LEVEL_TRACE "$*"; }
log_debug() { _log $LOG_LEVEL_DEBUG "$*"; }
log_info() { _log $LOG_LEVEL_INFO "$*"; }
log_notice() { _log $LOG_LEVEL_NOTICE "$*"; }
log_warning() { _log $LOG_LEVEL_WARNING "$*"; }
log_error() { _log $LOG_LEVEL_ERROR "$*"; }
log_critical() { _log $LOG_LEVEL_CRITICAL "$*"; }
log_emergency() { _log $LOG_LEVEL_EMERGENCY "$*"; }

# Alias for compatibility
log_msg() {
    local level="${1:-INFO}"
    local message="${2:-}"
    
    case "${level^^}" in
        TRACE) log_trace "$message" ;;
        DEBUG) log_debug "$message" ;;
        INFO) log_info "$message" ;;
        NOTICE) log_notice "$message" ;;
        WARNING|WARN) log_warning "$message" ;;
        ERROR|ERR) log_error "$message" ;;
        CRITICAL|CRIT) log_critical "$message" ;;
        EMERGENCY|EMERG) log_emergency "$message" ;;
        *) log_info "$message" ;;
    esac
}

# Set log level from string
set_log_level() {
    local level_str="${1:-INFO}"
    
    case "${level_str^^}" in
        TRACE) CURRENT_LOG_LEVEL=$LOG_LEVEL_TRACE ;;
        DEBUG) CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG ;;
        INFO) CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO ;;
        NOTICE) CURRENT_LOG_LEVEL=$LOG_LEVEL_NOTICE ;;
        WARNING|WARN) CURRENT_LOG_LEVEL=$LOG_LEVEL_WARNING ;;
        ERROR|ERR) CURRENT_LOG_LEVEL=$LOG_LEVEL_ERROR ;;
        CRITICAL|CRIT) CURRENT_LOG_LEVEL=$LOG_LEVEL_CRITICAL ;;
        EMERGENCY|EMERG) CURRENT_LOG_LEVEL=$LOG_LEVEL_EMERGENCY ;;
        *) 
            log_warning "Unknown log level: $level_str, defaulting to INFO"
            CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO
            ;;
    esac
    
    log_debug "Log level set to: ${LOG_LEVEL_NAMES[$CURRENT_LOG_LEVEL]}"
}

# ==============================================================================
# MODULE 5.2: OUTPUT FORMATTING FUNCTIONS
# ==============================================================================

# Print a colored message
print_color() {
    local color="$1"
    local message="$2"
    
    if [[ $EXTIPMON_COLOR_OUTPUT -eq 1 ]]; then
        echo -e "${color}${message}${NC}"
    else
        echo "$message"
    fi
}

# Print success message
print_success() {
    local message="$1"
    print_color "$COLOR_SUCCESS" "${ICON_SUCCESS} $message"
}

# Print error message
print_error() {
    local message="$1"
    print_color "$COLOR_ERROR" "${ICON_ERROR} $message"
}

# Print warning message
print_warning() {
    local message="$1"
    print_color "$COLOR_WARNING" "${ICON_WARNING} $message"
}

# Print info message
print_info() {
    local message="$1"
    print_color "$COLOR_INFO" "${ICON_INFO} $message"
}

# Print debug message (only if debug mode)
print_debug() {
    local message="$1"
    if [[ $EXTIPMON_DEBUG_MODE -eq 1 ]]; then
        print_color "$COLOR_DEBUG" "[DEBUG] $message"
    fi
}

# Print a header line
print_header() {
    local title="$1"
    local width="${2:-$EXTIPMON_TERM_COLS}"
    local char="${3:-═}"
    
    local title_len=${#title}
    local padding=$(( (width - title_len - 4) / 2 ))
    local line=""
    
    # Build padding
    for ((i=0; i<padding; i++)); do
        line+="$char"
    done
    
    if [[ $EXTIPMON_COLOR_OUTPUT -eq 1 ]]; then
        echo -e "${CLR256_SAPPHIRE}${line}${NC} ${CLR256_WHITE}${CLR_BOLD}${title}${NC} ${CLR256_SAPPHIRE}${line}${NC}"
    else
        echo "$line $title $line"
    fi
}

# Print a separator line
print_separator() {
    local width="${1:-$EXTIPMON_TERM_COLS}"
    local char="${2:-─}"
    local color="${3:-$CLR256_GRAY_8}"
    local line=""
    
    for ((i=0; i<width; i++)); do
        line+="$char"
    done
    
    if [[ $EXTIPMON_COLOR_OUTPUT -eq 1 ]]; then
        echo -e "${color}${line}${NC}"
    else
        echo "$line"
    fi
}

# Print a box around text
print_box() {
    local title="$1"
    local content="$2"
    local width="${3:-60}"
    
    local title_padded
    local content_lines
    
    # Top border
    echo -e "${CLR256_GRAY_8}${BOX_DTL}$(printf '%*s' "$((width-2))" | tr ' ' "$BOX_DH")${BOX_DTR}${NC}"
    
    # Title line
    title_padded=$(printf "%-$((width-4))s" "$title")
    echo -e "${CLR256_GRAY_8}${BOX_DV}${NC} ${CLR256_WHITE}${CLR_BOLD}${title_padded}${NC} ${CLR256_GRAY_8}${BOX_DV}${NC}"
    
    # Separator
    echo -e "${CLR256_GRAY_8}${BOX_DT_RIGHT}$(printf '%*s' "$((width-2))" | tr ' ' "$BOX_DH")${BOX_DT_LEFT}${NC}"
    
    # Content lines
    while IFS= read -r line; do
        local line_padded
        line_padded=$(printf "%-$((width-4))s" "$line")
        echo -e "${CLR256_GRAY_8}${BOX_DV}${NC} ${line_padded} ${CLR256_GRAY_8}${BOX_DV}${NC}"
    done <<< "$content"
    
    # Bottom border
    echo -e "${CLR256_GRAY_8}${BOX_DBL}$(printf '%*s' "$((width-2))" | tr ' ' "$BOX_DH")${BOX_DBR}${NC}"
}

# Print a table row
print_table_row() {
    local -a columns=("$@")
    local -a widths
    local output=""
    local separator="${CLR256_GRAY_8}│${NC}"
    
    # Default column widths
    widths=(15 20 12 10 15 10)
    
    for i in "${!columns[@]}"; do
        local col="${columns[$i]}"
        local width="${widths[$i]:-15}"
        local padded
        
        padded=$(printf "%-${width}s" "$col")
        output+="${padded:0:$width} $separator "
    done
    
    echo -e "$output"
}

# ==============================================================================
# MODULE 5.3: PROGRESS INDICATORS
# ==============================================================================

# Global spinner state
declare -g SPINNER_PID=""
declare -g SPINNER_ACTIVE=0

# Start a spinner
spinner_start() {
    local message="${1:-Working...}"
    local spinner_type="${2:-braille}"
    local -a spinner_chars
    
    # Select spinner type
    case "$spinner_type" in
        braille) spinner_chars=("${SPINNER_BRAILLE[@]}") ;;
        dots) spinner_chars=("${SPINNER_DOTS[@]}") ;;
        line) spinner_chars=("${SPINNER_LINE[@]}") ;;
        arc) spinner_chars=("${SPINNER_ARC[@]}") ;;
        circle) spinner_chars=("${SPINNER_CIRCLE[@]}") ;;
        clock) spinner_chars=("${SPINNER_CLOCK[@]}") ;;
        moon) spinner_chars=("${SPINNER_MOON[@]}") ;;
        *) spinner_chars=("${SPINNER_BRAILLE[@]}") ;;
    esac
    
    local count=${#spinner_chars[@]}
    local idx=0
    
    # Start spinner in background
    (
        while true; do
            printf "\r${CLR256_SAPPHIRE}${spinner_chars[$idx]}${NC} %s" "$message"
            idx=$(( (idx + 1) % count ))
            sleep 0.1
        done
    ) &
    
    SPINNER_PID=$!
    SPINNER_ACTIVE=1
    
    # Disable cursor
    tput civis 2>/dev/null
}

# Stop the spinner
spinner_stop() {
    local status="${1:-success}"
    local message="${2:-Done}"
    
    if [[ $SPINNER_ACTIVE -eq 1 ]] && [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
        SPINNER_PID=""
        SPINNER_ACTIVE=0
        
        # Clear spinner line
        printf "\r%*s\r" "$EXTIPMON_TERM_COLS" ""
        
        # Show status
        case "$status" in
            success) print_success "$message" ;;
            error) print_error "$message" ;;
            warning) print_warning "$message" ;;
            *) print_info "$message" ;;
        esac
        
        # Enable cursor
        tput cnorm 2>/dev/null
    fi
}

# Display a progress bar
progress_bar() {
    local current="$1"
    local total="$2"
    local width="${3:-50}"
    local label="${4:-Progress}"
    
    local percent=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    
    local bar=""
    for ((i=0; i<filled; i++)); do
        bar+="$PROGRESS_FILLED"
    done
    for ((i=0; i<empty; i++)); do
        bar+="$PROGRESS_EMPTY"
    done
    
    printf "\r${CLR256_GRAY_12}%s:${NC} ${CLR256_SAPPHIRE}[${CLR256_EMERALD}%s${CLR256_SAPPHIRE}]${NC} ${CLR256_WHITE}%3d%%${NC}" "$label" "$bar" "$percent"
    
    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

# Display a countdown timer
countdown_timer() {
    local seconds="$1"
    local message="${2:-Starting in}"
    
    while [[ $seconds -gt 0 ]]; do
        printf "\r${CLR256_YELLOW}${message}: %d seconds...${NC}" "$seconds"
        sleep 1
        ((seconds--))
    done
    
    printf "\r%*s\r" "$EXTIPMON_TERM_COLS" ""
}

# ==============================================================================
# MODULE 5.4: INPUT/OUTPUT HELPERS
# ==============================================================================

# Read user input with prompt
read_input() {
    local prompt="$1"
    local default="${2:-}"
    local secret="${3:-0}"
    local result
    
    if [[ -n "$default" ]]; then
        prompt="$prompt [$default]"
    fi
    
    if [[ $secret -eq 1 ]]; then
        read -r -s -p "$prompt: " result
        echo ""
    else
        read -r -p "$prompt: " result
    fi
    
    if [[ -z "$result" ]] && [[ -n "$default" ]]; then
        result="$default"
    fi
    
    echo "$result"
}

# Confirm yes/no
confirm() {
    local prompt="${1:-Are you sure?}"
    local default="${2:-n}"
    local response
    
    if [[ "${default,,}" == "y" ]]; then
        prompt="$prompt [Y/n]"
    else
        prompt="$prompt [y/N]"
    fi
    
    read -r -p "$prompt " response
    
    if [[ -z "$response" ]]; then
        response="$default"
    fi
    
    case "${response,,}" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# Select from menu
select_menu() {
    local title="$1"
    shift
    local -a options=("$@")
    local selection
    
    echo ""
    print_header "$title"
    echo ""
    
    for i in "${!options[@]}"; do
        echo "  $((i + 1)). ${options[$i]}"
    done
    
    echo ""
    read -r -p "Select option [1-${#options[@]}]: " selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#options[@]} ]]; then
        echo "${options[$((selection - 1))]}"
        return 0
    else
        echo ""
        return 1
    fi
}

# ==============================================================================
# MODULE 5.5: STRING MANIPULATION
# ==============================================================================

# Trim whitespace from string
trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo "$var"
}

# Convert to uppercase
to_upper() {
    echo "${*^^}"
}

# Convert to lowercase
to_lower() {
    echo "${*,,}"
}

# Capitalize first letter
capitalize() {
    local str="$*"
    echo "${str^}"
}

# Pad string to width
pad_string() {
    local str="$1"
    local width="$2"
    local align="${3:-left}"
    local pad_char="${4:- }"
    
    local len=${#str}
    local padding=$((width - len))
    
    if [[ $padding -le 0 ]]; then
        echo "${str:0:$width}"
        return
    fi
    
    case "$align" in
        left)
            printf "%s%*s" "$str" "$padding" | tr ' ' "$pad_char"
            ;;
        right)
            printf "%*s%s" "$padding" "$str" | tr ' ' "$pad_char"
            ;;
        center)
            local left=$((padding / 2))
            local right=$((padding - left))
            printf "%*s%s%*s" "$left" "" "$str" "$right" "" | tr ' ' "$pad_char"
            ;;
    esac
}

# Truncate string with ellipsis
truncate() {
    local str="$1"
    local max_len="${2:-50}"
    local ellipsis="${3:-...}"
    
    if [[ ${#str} -le $max_len ]]; then
        echo "$str"
    else
        echo "${str:0:$((max_len - ${#ellipsis}))}$ellipsis"
    fi
}

# Repeat string n times
repeat_string() {
    local str="$1"
    local count="$2"
    local result=""
    
    for ((i=0; i<count; i++)); do
        result+="$str"
    done
    
    echo "$result"
}

# Join array with delimiter
join_array() {
    local delimiter="$1"
    shift
    local -a array=("$@")
    local result=""
    
    for i in "${!array[@]}"; do
        if [[ $i -gt 0 ]]; then
            result+="$delimiter"
        fi
        result+="${array[$i]}"
    done
    
    echo "$result"
}

# Split string into array
split_string() {
    local str="$1"
    local delimiter="${2:-,}"
    local -n result_array="$3"
    
    IFS="$delimiter" read -ra result_array <<< "$str"
}

# ==============================================================================
# MODULE 5.6: NUMERIC FUNCTIONS
# ==============================================================================

# Format bytes to human readable
format_bytes() {
    local bytes="$1"
    local precision="${2:-2}"
    
    if [[ $bytes -lt 1024 ]]; then
        echo "${bytes} B"
    elif [[ $bytes -lt 1048576 ]]; then
        printf "%.${precision}f KB" "$(echo "scale=$precision; $bytes / 1024" | bc)"
    elif [[ $bytes -lt 1073741824 ]]; then
        printf "%.${precision}f MB" "$(echo "scale=$precision; $bytes / 1048576" | bc)"
    elif [[ $bytes -lt 1099511627776 ]]; then
        printf "%.${precision}f GB" "$(echo "scale=$precision; $bytes / 1073741824" | bc)"
    else
        printf "%.${precision}f TB" "$(echo "scale=$precision; $bytes / 1099511627776" | bc)"
    fi
}

# Format number with commas
format_number() {
    local number="$1"
    echo "$number" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

# Format duration (seconds to human readable)
format_duration() {
    local seconds="$1"
    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    
    local result=""
    
    if [[ $days -gt 0 ]]; then
        result+="${days}d "
    fi
    if [[ $hours -gt 0 ]] || [[ $days -gt 0 ]]; then
        result+="${hours}h "
    fi
    if [[ $minutes -gt 0 ]] || [[ $hours -gt 0 ]] || [[ $days -gt 0 ]]; then
        result+="${minutes}m "
    fi
    result+="${secs}s"
    
    echo "$result"
}

# Format timestamp to ISO 8601
format_timestamp() {
    local timestamp="${1:-$(date +%s)}"
    date -d "@$timestamp" -Iseconds 2>/dev/null || date -r "$timestamp" -Iseconds 2>/dev/null || echo "Invalid timestamp"
}

# Calculate percentage
calc_percentage() {
    local value="$1"
    local total="$2"
    local precision="${3:-2}"
    
    if [[ $total -eq 0 ]]; then
        echo "0"
    else
        printf "%.${precision}f" "$(echo "scale=$((precision + 2)); $value * 100 / $total" | bc)"
    fi
}

# ==============================================================================
# MODULE 5.7: NETWORK UTILITY FUNCTIONS
# ==============================================================================

# Check if IP is valid IPv4
is_valid_ipv4() {
    local ip="$1"
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if [[ ! $ip =~ $regex ]]; then
        return 1
    fi
    
    local IFS='.'
    read -ra octets <<< "$ip"
    
    for octet in "${octets[@]}"; do
        if [[ $octet -lt 0 ]] || [[ $octet -gt 255 ]]; then
            return 1
        fi
    done
    
    return 0
}

# Check if IP is valid IPv6
is_valid_ipv6() {
    local ip="$1"
    local regex='^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$|^::([0-9a-fA-F]{0,4}:){0,6}[0-9a-fA-F]{0,4}$|^[0-9a-fA-F]{0,4}::([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}$'
    
    [[ $ip =~ $regex ]]
}

# Check if IP is private (RFC 1918)
is_private_ip() {
    local ip="$1"
    
    if ! is_valid_ipv4 "$ip"; then
        return 1
    fi
    
    local IFS='.'
    read -ra octets <<< "$ip"
    
    # 10.0.0.0/8
    if [[ ${octets[0]} -eq 10 ]]; then
        return 0
    fi
    
    # 172.16.0.0/12
    if [[ ${octets[0]} -eq 172 ]] && [[ ${octets[1]} -ge 16 ]] && [[ ${octets[1]} -le 31 ]]; then
        return 0
    fi
    
    # 192.168.0.0/16
    if [[ ${octets[0]} -eq 192 ]] && [[ ${octets[1]} -eq 168 ]]; then
        return 0
    fi
    
    return 1
}

# Check if IP is loopback
is_loopback_ip() {
    local ip="$1"
    
    if [[ $ip == "127."* ]] || [[ $ip == "::1" ]] || [[ $ip == "localhost" ]]; then
        return 0
    fi
    
    return 1
}

# Check if IP is multicast
is_multicast_ip() {
    local ip="$1"
    
    if ! is_valid_ipv4 "$ip"; then
        return 1
    fi
    
    local IFS='.'
    read -ra octets <<< "$ip"
    
    # 224.0.0.0/4 (224-239)
    if [[ ${octets[0]} -ge 224 ]] && [[ ${octets[0]} -le 239 ]]; then
        return 0
    fi
    
    return 1
}

# Check if IP is link-local
is_link_local_ip() {
    local ip="$1"
    
    if ! is_valid_ipv4 "$ip"; then
        return 1
    fi
    
    local IFS='.'
    read -ra octets <<< "$ip"
    
    # 169.254.0.0/16
    if [[ ${octets[0]} -eq 169 ]] && [[ ${octets[1]} -eq 254 ]]; then
        return 0
    fi
    
    return 1
}

# Check if IP is external (public)
is_external_ip() {
    local ip="$1"
    
    if ! is_valid_ipv4 "$ip" && ! is_valid_ipv6 "$ip"; then
        return 1
    fi
    
    if is_private_ip "$ip" || is_loopback_ip "$ip" || is_multicast_ip "$ip" || is_link_local_ip "$ip"; then
        return 1
    fi
    
    return 0
}

# Get port service name
get_port_service() {
    local port="$1"
    local port_info="${PORT_DATABASE[$port]:-}"
    
    if [[ -n "$port_info" ]]; then
        echo "${port_info%%|*}"
    else
        echo "Unknown"
    fi
}

# Get port description
get_port_description() {
    local port="$1"
    local port_info="${PORT_DATABASE[$port]:-}"
    
    if [[ -n "$port_info" ]]; then
        local IFS='|'
        read -ra parts <<< "$port_info"
        echo "${parts[1]:-Unknown}"
    else
        echo "Unknown service"
    fi
}

# Get port risk level
get_port_risk() {
    local port="$1"
    local port_info="${PORT_DATABASE[$port]:-}"
    
    if [[ -n "$port_info" ]]; then
        local IFS='|'
        read -ra parts <<< "$port_info"
        echo "${parts[2]:-UNKNOWN}"
    else
        echo "UNKNOWN"
    fi
}

# Get country flag emoji
get_country_flag() {
    local country_code="${1:-UNK}"
    echo "${COUNTRY_FLAGS[${country_code^^}]:-🏳️}"
}

# Format IP with geo info
format_ip_with_geo() {
    local ip="$1"
    local country="${2:-UNK}"
    local city="${3:-}"
    
    local flag
    flag=$(get_country_flag "$country")
    
    if [[ -n "$city" ]]; then
        echo "$ip ($flag $city, $country)"
    else
        echo "$ip ($flag $country)"
    fi
}



# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 6: CONNECTION TRACKING SUBSYSTEM                             ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 6.1: CONNECTION STATE MANAGEMENT
# ==============================================================================

# Connection states
declare -r CONN_STATE_NEW="NEW"
declare -r CONN_STATE_ESTABLISHED="ESTABLISHED"
declare -r CONN_STATE_ACTIVE="ACTIVE"
declare -r CONN_STATE_IDLE="IDLE"
declare -r CONN_STATE_CLOSING="CLOSING"
declare -r CONN_STATE_CLOSED="CLOSED"
declare -r CONN_STATE_TIMEOUT="TIMEOUT"

# Connection tracking data structures
declare -gA ACTIVE_CONNECTIONS=()
declare -gA CONNECTION_START_TIMES=()
declare -gA CONNECTION_LAST_SEEN=()
declare -gA CONNECTION_BYTES_IN=()
declare -gA CONNECTION_BYTES_OUT=()
declare -gA CONNECTION_PACKETS_IN=()
declare -gA CONNECTION_PACKETS_OUT=()
declare -gA CONNECTION_STATES=()
declare -gA CONNECTION_PROTOCOLS=()
declare -gA CONNECTION_DIRECTIONS=()
declare -gA CONNECTION_PORTS=()
declare -gA CONNECTION_GEO_COUNTRY=()
declare -gA CONNECTION_GEO_CITY=()
declare -gA CONNECTION_HOSTNAMES=()
declare -gA CONNECTION_THREAT_LEVELS=()

# Connection history for disconnection tracking
declare -gA CONNECTION_HISTORY=()
declare -gA DISCONNECTION_TIMES=()
declare -gA DISCONNECTION_DURATIONS=()

# Statistics
declare -g TOTAL_CONNECTIONS=0
declare -g ACTIVE_CONNECTION_COUNT=0
declare -g TOTAL_BYTES_IN=0
declare -g TOTAL_BYTES_OUT=0
declare -g TOTAL_PACKETS_IN=0
declare -g TOTAL_PACKETS_OUT=0
declare -g TOTAL_DISCONNECTIONS=0

# Initialize connection tracking
init_connection_tracking() {
    log_info "Initializing connection tracking subsystem"
    
    # Clear all arrays
    ACTIVE_CONNECTIONS=()
    CONNECTION_START_TIMES=()
    CONNECTION_LAST_SEEN=()
    CONNECTION_BYTES_IN=()
    CONNECTION_BYTES_OUT=()
    CONNECTION_PACKETS_IN=()
    CONNECTION_PACKETS_OUT=()
    CONNECTION_STATES=()
    CONNECTION_PROTOCOLS=()
    CONNECTION_DIRECTIONS=()
    CONNECTION_PORTS=()
    CONNECTION_GEO_COUNTRY=()
    CONNECTION_GEO_CITY=()
    CONNECTION_HOSTNAMES=()
    CONNECTION_THREAT_LEVELS=()
    CONNECTION_HISTORY=()
    DISCONNECTION_TIMES=()
    DISCONNECTION_DURATIONS=()
    
    # Reset statistics
    TOTAL_CONNECTIONS=0
    ACTIVE_CONNECTION_COUNT=0
    TOTAL_BYTES_IN=0
    TOTAL_BYTES_OUT=0
    TOTAL_PACKETS_IN=0
    TOTAL_PACKETS_OUT=0
    TOTAL_DISCONNECTIONS=0
    
    log_debug "Connection tracking initialized"
}

# Generate connection key from IP and port
generate_connection_key() {
    local ip="$1"
    local port="${2:-0}"
    local protocol="${3:-TCP}"
    
    echo "${ip}:${port}:${protocol}"
}

# Register a new connection
register_connection() {
    local ip="$1"
    local port="${2:-0}"
    local protocol="${3:-TCP}"
    local direction="${4:-IN}"
    local timestamp="${5:-$(date +%s)}"
    
    local key
    key=$(generate_connection_key "$ip" "$port" "$protocol")
    
    # Check if connection already exists
    if [[ -n "${ACTIVE_CONNECTIONS[$key]:-}" ]]; then
        # Update existing connection
        update_connection "$ip" "$port" "$protocol" 0 0 1
        return 0
    fi
    
    # Register new connection
    ACTIVE_CONNECTIONS[$key]=1
    CONNECTION_START_TIMES[$key]=$timestamp
    CONNECTION_LAST_SEEN[$key]=$timestamp
    CONNECTION_BYTES_IN[$key]=0
    CONNECTION_BYTES_OUT[$key]=0
    CONNECTION_PACKETS_IN[$key]=0
    CONNECTION_PACKETS_OUT[$key]=0
    CONNECTION_STATES[$key]=$CONN_STATE_ESTABLISHED
    CONNECTION_PROTOCOLS[$key]=$protocol
    CONNECTION_DIRECTIONS[$key]=$direction
    CONNECTION_PORTS[$key]=$port
    CONNECTION_GEO_COUNTRY[$key]="UNK"
    CONNECTION_GEO_CITY[$key]=""
    CONNECTION_HOSTNAMES[$key]=""
    CONNECTION_THREAT_LEVELS[$key]="NONE"
    
    # Update statistics
    ((TOTAL_CONNECTIONS++))
    ((ACTIVE_CONNECTION_COUNT++))
    
    # Format timestamp for display
    local connect_time
    connect_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    
    # Log connection event
    log_connection_event "CONNECTED" "$ip" "$port" "$protocol" "$direction" "$connect_time"
    
    return 0
}

# Update an existing connection
update_connection() {
    local ip="$1"
    local port="${2:-0}"
    local protocol="${3:-TCP}"
    local bytes_in="${4:-0}"
    local bytes_out="${5:-0}"
    local packets="${6:-1}"
    local timestamp="${7:-$(date +%s)}"
    
    local key
    key=$(generate_connection_key "$ip" "$port" "$protocol")
    
    # Check if connection exists
    if [[ -z "${ACTIVE_CONNECTIONS[$key]:-}" ]]; then
        # Connection doesn't exist, register it
        register_connection "$ip" "$port" "$protocol" "IN" "$timestamp"
        return 0
    fi
    
    # Update last seen time
    CONNECTION_LAST_SEEN[$key]=$timestamp
    
    # Update byte counters
    CONNECTION_BYTES_IN[$key]=$((${CONNECTION_BYTES_IN[$key]:-0} + bytes_in))
    CONNECTION_BYTES_OUT[$key]=$((${CONNECTION_BYTES_OUT[$key]:-0} + bytes_out))
    
    # Update packet counters
    if [[ "${CONNECTION_DIRECTIONS[$key]:-IN}" == "IN" ]]; then
        CONNECTION_PACKETS_IN[$key]=$((${CONNECTION_PACKETS_IN[$key]:-0} + packets))
        ((TOTAL_PACKETS_IN += packets))
    else
        CONNECTION_PACKETS_OUT[$key]=$((${CONNECTION_PACKETS_OUT[$key]:-0} + packets))
        ((TOTAL_PACKETS_OUT += packets))
    fi
    
    # Update total bytes
    ((TOTAL_BYTES_IN += bytes_in))
    ((TOTAL_BYTES_OUT += bytes_out))
    
    # Update state to active
    CONNECTION_STATES[$key]=$CONN_STATE_ACTIVE
    
    return 0
}

# Unregister a connection (disconnect)
unregister_connection() {
    local ip="$1"
    local port="${2:-0}"
    local protocol="${3:-TCP}"
    local timestamp="${4:-$(date +%s)}"
    
    local key
    key=$(generate_connection_key "$ip" "$port" "$protocol")
    
    # Check if connection exists
    if [[ -z "${ACTIVE_CONNECTIONS[$key]:-}" ]]; then
        log_debug "Attempted to unregister non-existent connection: $key"
        return 1
    fi
    
    # Calculate connection duration
    local start_time="${CONNECTION_START_TIMES[$key]:-$timestamp}"
    local duration=$((timestamp - start_time))
    
    # Store in history
    CONNECTION_HISTORY[$key]="${CONNECTION_START_TIMES[$key]}|$timestamp|$duration"
    DISCONNECTION_TIMES[$key]=$timestamp
    DISCONNECTION_DURATIONS[$key]=$duration
    
    # Format timestamps for display
    local disconnect_time
    disconnect_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$timestamp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    
    # Log disconnection event
    log_disconnection_event "$ip" "$port" "$protocol" "$disconnect_time" "$duration"
    
    # Update statistics
    ((ACTIVE_CONNECTION_COUNT--))
    ((TOTAL_DISCONNECTIONS++))
    
    # Remove from active connections
    unset "ACTIVE_CONNECTIONS[$key]"
    unset "CONNECTION_START_TIMES[$key]"
    unset "CONNECTION_LAST_SEEN[$key]"
    unset "CONNECTION_BYTES_IN[$key]"
    unset "CONNECTION_BYTES_OUT[$key]"
    unset "CONNECTION_PACKETS_IN[$key]"
    unset "CONNECTION_PACKETS_OUT[$key]"
    unset "CONNECTION_STATES[$key]"
    unset "CONNECTION_PROTOCOLS[$key]"
    unset "CONNECTION_DIRECTIONS[$key]"
    unset "CONNECTION_PORTS[$key]"
    unset "CONNECTION_GEO_COUNTRY[$key]"
    unset "CONNECTION_GEO_CITY[$key]"
    unset "CONNECTION_HOSTNAMES[$key]"
    unset "CONNECTION_THREAT_LEVELS[$key]"
    
    return 0
}

# Check for timed out connections
check_connection_timeouts() {
    local timeout="${1:-$EXTIPMON_CONNECTION_TIMEOUT}"
    local current_time
    current_time=$(date +%s)
    
    local timed_out=0
    
    for key in "${!ACTIVE_CONNECTIONS[@]}"; do
        local last_seen="${CONNECTION_LAST_SEEN[$key]:-0}"
        local idle_time=$((current_time - last_seen))
        
        if [[ $idle_time -gt $timeout ]]; then
            # Extract IP and port from key
            local ip="${key%%:*}"
            local rest="${key#*:}"
            local port="${rest%%:*}"
            local protocol="${rest##*:}"
            
            # Mark as timed out and unregister
            CONNECTION_STATES[$key]=$CONN_STATE_TIMEOUT
            unregister_connection "$ip" "$port" "$protocol" "$current_time"
            
            ((timed_out++))
        fi
    done
    
    if [[ $timed_out -gt 0 ]]; then
        log_debug "Cleaned up $timed_out timed out connections"
    fi
    
    return $timed_out
}

# Log connection event
log_connection_event() {
    local event_type="$1"
    local ip="$2"
    local port="$3"
    local protocol="$4"
    local direction="$5"
    local timestamp="$6"
    
    local country="${CONNECTION_GEO_COUNTRY[$(generate_connection_key "$ip" "$port" "$protocol")]:-UNK}"
    local flag
    flag=$(get_country_flag "$country")
    
    # Console output
    if [[ $EXTIPMON_VERBOSE -eq 1 ]]; then
        echo -e "${COLOR_CONNECTED}${ICON_CONNECTED}${NC} ${CLR256_WHITE}${ip}${NC} Connected at ${CLR256_YELLOW}${timestamp}${NC} ${flag} - (live connection timer)"
    fi
    
    # JSON log
    if [[ "${EXTIPMON_LOG_FORMAT:-text}" == "json" ]] && [[ -n "${EXTIPMON_CONNECTION_LOG:-}" ]]; then
        local json_event
        json_event=$(cat <<EOF
{"event":"CONNECTED","timestamp":"$timestamp","ip":"$ip","port":$port,"protocol":"$protocol","direction":"$direction","country":"$country"}
EOF
)
        echo "$json_event" >> "$EXTIPMON_CONNECTION_LOG"
    fi
    
    log_info "Connection: $ip:$port ($protocol) - $direction - $country"
}

# Log disconnection event
log_disconnection_event() {
    local ip="$1"
    local port="$2"
    local protocol="$3"
    local timestamp="$4"
    local duration="$5"
    
    local formatted_duration
    formatted_duration=$(format_duration "$duration")
    
    # Console output
    if [[ $EXTIPMON_VERBOSE -eq 1 ]]; then
        echo -e "${COLOR_DISCONNECTED}${ICON_DISCONNECTED}${NC} ${CLR256_WHITE}${ip}${NC} Disconnected at ${CLR256_YELLOW}${timestamp}${NC} - (connection duration: ${formatted_duration})"
    fi
    
    # JSON log
    if [[ "${EXTIPMON_LOG_FORMAT:-text}" == "json" ]] && [[ -n "${EXTIPMON_CONNECTION_LOG:-}" ]]; then
        local json_event
        json_event=$(cat <<EOF
{"event":"DISCONNECTED","timestamp":"$timestamp","ip":"$ip","port":$port,"protocol":"$protocol","duration_seconds":$duration,"duration_formatted":"$formatted_duration"}
EOF
)
        echo "$json_event" >> "$EXTIPMON_CONNECTION_LOG"
    fi
    
    log_info "Disconnection: $ip:$port ($protocol) after $formatted_duration"
}

# Get connection info
get_connection_info() {
    local ip="$1"
    local port="${2:-0}"
    local protocol="${3:-TCP}"
    
    local key
    key=$(generate_connection_key "$ip" "$port" "$protocol")
    
    if [[ -z "${ACTIVE_CONNECTIONS[$key]:-}" ]]; then
        echo ""
        return 1
    fi
    
    local start_time="${CONNECTION_START_TIMES[$key]:-0}"
    local last_seen="${CONNECTION_LAST_SEEN[$key]:-0}"
    local current_time
    current_time=$(date +%s)
    local duration=$((current_time - start_time))
    local idle=$((current_time - last_seen))
    
    local bytes_in="${CONNECTION_BYTES_IN[$key]:-0}"
    local bytes_out="${CONNECTION_BYTES_OUT[$key]:-0}"
    local state="${CONNECTION_STATES[$key]:-UNKNOWN}"
    local direction="${CONNECTION_DIRECTIONS[$key]:-IN}"
    local country="${CONNECTION_GEO_COUNTRY[$key]:-UNK}"
    local threat="${CONNECTION_THREAT_LEVELS[$key]:-NONE}"
    
    echo "${ip}|${port}|${protocol}|${start_time}|${duration}|${idle}|${bytes_in}|${bytes_out}|${state}|${direction}|${country}|${threat}"
}

# Get all active connections as formatted list
get_active_connections_list() {
    local sort_by="${1:-duration}"
    local limit="${2:-50}"
    local current_time
    current_time=$(date +%s)
    
    local -a connections=()
    
    for key in "${!ACTIVE_CONNECTIONS[@]}"; do
        local ip="${key%%:*}"
        local rest="${key#*:}"
        local port="${rest%%:*}"
        local protocol="${rest##*:}"
        
        local start_time="${CONNECTION_START_TIMES[$key]:-0}"
        local duration=$((current_time - start_time))
        local bytes=$((${CONNECTION_BYTES_IN[$key]:-0} + ${CONNECTION_BYTES_OUT[$key]:-0}))
        local country="${CONNECTION_GEO_COUNTRY[$key]:-UNK}"
        local direction="${CONNECTION_DIRECTIONS[$key]:-IN}"
        
        connections+=("$duration|$ip|$port|$protocol|$bytes|$country|$direction")
    done
    
    # Sort connections
    case "$sort_by" in
        duration)
            printf '%s\n' "${connections[@]}" | sort -t'|' -k1 -nr | head -n "$limit"
            ;;
        bytes)
            printf '%s\n' "${connections[@]}" | sort -t'|' -k5 -nr | head -n "$limit"
            ;;
        ip)
            printf '%s\n' "${connections[@]}" | sort -t'|' -k2 | head -n "$limit"
            ;;
        *)
            printf '%s\n' "${connections[@]}" | head -n "$limit"
            ;;
    esac
}

# Get connection statistics
get_connection_stats() {
    local current_time
    current_time=$(date +%s)
    
    local total_duration=0
    local max_duration=0
    local oldest_connection=""
    
    for key in "${!ACTIVE_CONNECTIONS[@]}"; do
        local start_time="${CONNECTION_START_TIMES[$key]:-$current_time}"
        local duration=$((current_time - start_time))
        
        ((total_duration += duration))
        
        if [[ $duration -gt $max_duration ]]; then
            max_duration=$duration
            oldest_connection="$key"
        fi
    done
    
    local avg_duration=0
    if [[ $ACTIVE_CONNECTION_COUNT -gt 0 ]]; then
        avg_duration=$((total_duration / ACTIVE_CONNECTION_COUNT))
    fi
    
    echo "active=$ACTIVE_CONNECTION_COUNT"
    echo "total=$TOTAL_CONNECTIONS"
    echo "disconnections=$TOTAL_DISCONNECTIONS"
    echo "bytes_in=$TOTAL_BYTES_IN"
    echo "bytes_out=$TOTAL_BYTES_OUT"
    echo "packets_in=$TOTAL_PACKETS_IN"
    echo "packets_out=$TOTAL_PACKETS_OUT"
    echo "avg_duration=$avg_duration"
    echo "max_duration=$max_duration"
    echo "oldest_connection=$oldest_connection"
}


# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 7: GEOIP AND THREAT INTELLIGENCE                             ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 7.1: GEOIP DATABASE AND LOOKUP FUNCTIONS
# ==============================================================================

# GeoIP Cache
declare -gA GEOIP_CACHE=()
declare -gA GEOIP_CACHE_TIMESTAMPS=()

# Country Code to Name Mapping
declare -A COUNTRY_NAMES=(
    # Americas
    ["US"]="United States" ["CA"]="Canada" ["MX"]="Mexico" ["BR"]="Brazil"
    ["AR"]="Argentina" ["CL"]="Chile" ["CO"]="Colombia" ["PE"]="Peru"
    ["VE"]="Venezuela" ["EC"]="Ecuador" ["UY"]="Uruguay" ["PY"]="Paraguay"
    ["BO"]="Bolivia" ["CU"]="Cuba" ["DO"]="Dominican Republic"
    ["JM"]="Jamaica" ["PR"]="Puerto Rico" ["TT"]="Trinidad and Tobago"
    ["CR"]="Costa Rica" ["PA"]="Panama" ["GT"]="Guatemala" ["HN"]="Honduras"
    ["SV"]="El Salvador" ["NI"]="Nicaragua" ["BZ"]="Belize"
    
    # Europe
    ["GB"]="United Kingdom" ["DE"]="Germany" ["FR"]="France" ["IT"]="Italy"
    ["ES"]="Spain" ["PT"]="Portugal" ["NL"]="Netherlands" ["BE"]="Belgium"
    ["AT"]="Austria" ["CH"]="Switzerland" ["SE"]="Sweden" ["NO"]="Norway"
    ["DK"]="Denmark" ["FI"]="Finland" ["IS"]="Iceland" ["IE"]="Ireland"
    ["PL"]="Poland" ["CZ"]="Czech Republic" ["SK"]="Slovakia" ["HU"]="Hungary"
    ["RO"]="Romania" ["BG"]="Bulgaria" ["GR"]="Greece" ["HR"]="Croatia"
    ["SI"]="Slovenia" ["RS"]="Serbia" ["BA"]="Bosnia and Herzegovina"
    ["MK"]="North Macedonia" ["ME"]="Montenegro" ["AL"]="Albania"
    ["LT"]="Lithuania" ["LV"]="Latvia" ["EE"]="Estonia" ["BY"]="Belarus"
    ["UA"]="Ukraine" ["MD"]="Moldova" ["RU"]="Russia" ["LU"]="Luxembourg"
    ["MT"]="Malta" ["CY"]="Cyprus"
    
    # Asia
    ["CN"]="China" ["JP"]="Japan" ["KR"]="South Korea" ["KP"]="North Korea"
    ["IN"]="India" ["PK"]="Pakistan" ["BD"]="Bangladesh" ["LK"]="Sri Lanka"
    ["NP"]="Nepal" ["BT"]="Bhutan" ["MM"]="Myanmar" ["TH"]="Thailand"
    ["VN"]="Vietnam" ["LA"]="Laos" ["KH"]="Cambodia" ["MY"]="Malaysia"
    ["SG"]="Singapore" ["ID"]="Indonesia" ["PH"]="Philippines" ["TW"]="Taiwan"
    ["HK"]="Hong Kong" ["MO"]="Macau" ["MN"]="Mongolia" ["KZ"]="Kazakhstan"
    ["UZ"]="Uzbekistan" ["TM"]="Turkmenistan" ["TJ"]="Tajikistan"
    ["KG"]="Kyrgyzstan" ["AF"]="Afghanistan" ["IR"]="Iran" ["IQ"]="Iraq"
    ["SY"]="Syria" ["JO"]="Jordan" ["LB"]="Lebanon" ["IL"]="Israel"
    ["PS"]="Palestine" ["SA"]="Saudi Arabia" ["AE"]="United Arab Emirates"
    ["QA"]="Qatar" ["KW"]="Kuwait" ["BH"]="Bahrain" ["OM"]="Oman"
    ["YE"]="Yemen" ["TR"]="Turkey" ["AZ"]="Azerbaijan" ["GE"]="Georgia"
    ["AM"]="Armenia"
    
    # Africa
    ["EG"]="Egypt" ["ZA"]="South Africa" ["NG"]="Nigeria" ["KE"]="Kenya"
    ["ET"]="Ethiopia" ["GH"]="Ghana" ["TZ"]="Tanzania" ["UG"]="Uganda"
    ["DZ"]="Algeria" ["MA"]="Morocco" ["TN"]="Tunisia" ["LY"]="Libya"
    ["SD"]="Sudan" ["SS"]="South Sudan" ["SN"]="Senegal" ["ML"]="Mali"
    ["NE"]="Niger" ["TD"]="Chad" ["CM"]="Cameroon" ["CI"]="Ivory Coast"
    ["ZW"]="Zimbabwe" ["ZM"]="Zambia" ["MW"]="Malawi" ["MZ"]="Mozambique"
    ["AO"]="Angola" ["BW"]="Botswana" ["NA"]="Namibia" ["RW"]="Rwanda"
    ["BI"]="Burundi" ["SO"]="Somalia" ["MG"]="Madagascar" ["MU"]="Mauritius"
    
    # Oceania
    ["AU"]="Australia" ["NZ"]="New Zealand" ["FJ"]="Fiji"
    ["PG"]="Papua New Guinea" ["SB"]="Solomon Islands" ["VU"]="Vanuatu"
    ["WS"]="Samoa" ["TO"]="Tonga"
    
    # Special
    ["UNK"]="Unknown" ["XX"]="Unknown" ["N/A"]="Unknown"
)

# ASN to Organization Mapping (Top ISPs and Cloud Providers)
declare -A ASN_ORGANIZATIONS=(
    # Major Cloud Providers
    ["AS15169"]="Google LLC"
    ["AS16509"]="Amazon.com, Inc."
    ["AS14618"]="Amazon Web Services"
    ["AS8075"]="Microsoft Corporation"
    ["AS13335"]="Cloudflare, Inc."
    ["AS32934"]="Facebook, Inc."
    ["AS20940"]="Akamai Technologies"
    ["AS54113"]="Fastly, Inc."
    ["AS14061"]="DigitalOcean, LLC"
    ["AS63949"]="Linode, LLC"
    ["AS20473"]="Vultr Holdings"
    ["AS24940"]="Hetzner Online GmbH"
    ["AS16276"]="OVH SAS"
    ["AS45102"]="Alibaba Cloud"
    ["AS37963"]="Alibaba (China)"
    ["AS45090"]="Tencent Cloud"
    
    # Major ISPs - United States
    ["AS7922"]="Comcast Cable Communications"
    ["AS22773"]="Cox Communications"
    ["AS701"]="Verizon Business"
    ["AS7018"]="AT&T Services"
    ["AS209"]="CenturyLink"
    ["AS33363"]="Charter Communications"
    ["AS11426"]="TWC"
    ["AS10796"]="Time Warner Cable"
    
    # Major ISPs - Europe
    ["AS3320"]="Deutsche Telekom AG"
    ["AS3215"]="Orange S.A."
    ["AS5410"]="Bouygues Telecom SA"
    ["AS12322"]="Free SAS"
    ["AS2856"]="British Telecommunications"
    ["AS5089"]="Virgin Media Limited"
    ["AS3269"]="Telecom Italia"
    ["AS12479"]="Orange Espagne SA"
    ["AS3352"]="Telefonica De Espana"
    ["AS6830"]="Liberty Global Europe"
    ["AS8560"]="IONOS SE"
    
    # Major ISPs - Asia
    ["AS4134"]="China Telecom"
    ["AS4837"]="China Unicom"
    ["AS4812"]="China Telecom (Shanghai)"
    ["AS9808"]="China Mobile"
    ["AS2516"]="KDDI Corporation"
    ["AS17676"]="SoftBank Corp."
    ["AS4713"]="NTT Communications"
    ["AS4766"]="Korea Telecom"
    ["AS9318"]="SK Broadband Co Ltd"
    ["AS55836"]="Reliance Jio"
    ["AS9829"]="BSNL India"
    ["AS45609"]="Bharti Airtel"
    
    # VPN and Anonymization Services (High Risk)
    ["AS9009"]="M247 Ltd"
    ["AS136787"]="TEFINCOM S.A."
    ["AS212238"]="Datacamp Limited"
    ["AS62041"]="Telecom Italia Sparkle"
    ["AS209"]="CenturyLink"
    
    # Known Threat Actors (High Risk)
    ["AS4134"]="China Telecom (State-owned)"
    ["AS12389"]="Rostelecom"
    ["AS8342"]="RTCOMM-AS"
    ["AS25513"]="PJSC MTS"
)

# Threat intelligence lists (IP ranges by country/organization)
declare -A THREAT_INDICATORS=(
    # Known malicious ASNs
    ["BULLETPROOF_HOSTING"]="AS44477 AS58271 AS49981 AS203020"
    ["TOR_EXIT_NODES"]="TOR"
    ["KNOWN_BOTNETS"]="BOTNET"
    ["SCANNERS"]="SCANNER"
    ["BRUTE_FORCE"]="BRUTEFORCE"
)

# GeoIP lookup function (uses multiple free APIs)
lookup_geoip() {
    local ip="$1"
    local cache_key="$ip"
    local current_time
    current_time=$(date +%s)
    
    # Check cache first
    if [[ -n "${GEOIP_CACHE[$cache_key]:-}" ]]; then
        local cache_time="${GEOIP_CACHE_TIMESTAMPS[$cache_key]:-0}"
        local age=$((current_time - cache_time))
        
        if [[ $age -lt ${EXTIPMON_GEOIP_CACHE_TTL:-86400} ]]; then
            echo "${GEOIP_CACHE[$cache_key]}"
            return 0
        fi
    fi
    
    # Skip private IPs
    if is_private_ip "$ip" || is_loopback_ip "$ip"; then
        GEOIP_CACHE[$cache_key]="PRIVATE|N/A|N/A|N/A|N/A"
        GEOIP_CACHE_TIMESTAMPS[$cache_key]=$current_time
        echo "PRIVATE|N/A|N/A|N/A|N/A"
        return 0
    fi
    
    local country="UNK"
    local city=""
    local region=""
    local isp=""
    local asn=""
    
    # Try ip-api.com first (45 requests/minute, no key needed)
    local response
    response=$(curl -s --max-time 5 "http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,isp,as" 2>/dev/null)
    
    if [[ -n "$response" ]] && [[ "$response" != *"error"* ]]; then
        local status
        status=$(echo "$response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        
        if [[ "$status" == "success" ]]; then
            country=$(echo "$response" | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4)
            city=$(echo "$response" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
            region=$(echo "$response" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
            isp=$(echo "$response" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
            asn=$(echo "$response" | grep -o '"as":"[^"]*"' | cut -d'"' -f4 | cut -d' ' -f1)
        fi
    fi
    
    # Fallback to ipinfo.io if first lookup failed
    if [[ "$country" == "UNK" ]] || [[ -z "$country" ]]; then
        response=$(curl -s --max-time 5 "https://ipinfo.io/${ip}/json" 2>/dev/null)
        
        if [[ -n "$response" ]]; then
            country=$(echo "$response" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
            city=$(echo "$response" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
            region=$(echo "$response" | grep -o '"region":"[^"]*"' | cut -d'"' -f4)
            local org
            org=$(echo "$response" | grep -o '"org":"[^"]*"' | cut -d'"' -f4)
            isp="${org:-Unknown}"
            asn=$(echo "$org" | grep -oE 'AS[0-9]+' | head -1)
        fi
    fi
    
    # Default if still unknown
    country="${country:-UNK}"
    city="${city:-Unknown}"
    region="${region:-Unknown}"
    isp="${isp:-Unknown}"
    asn="${asn:-Unknown}"
    
    # Cache result
    local result="${country}|${city}|${region}|${isp}|${asn}"
    GEOIP_CACHE[$cache_key]="$result"
    GEOIP_CACHE_TIMESTAMPS[$cache_key]=$current_time
    
    echo "$result"
}

# Get country name from code
get_country_name() {
    local code="${1:-UNK}"
    echo "${COUNTRY_NAMES[${code^^}]:-Unknown}"
}

# Get ASN organization
get_asn_organization() {
    local asn="${1:-}"
    echo "${ASN_ORGANIZATIONS[$asn]:-Unknown}"
}

# ==============================================================================
# MODULE 7.2: THREAT INTELLIGENCE FUNCTIONS
# ==============================================================================

# Threat level constants
declare -r THREAT_LEVEL_NONE=0
declare -r THREAT_LEVEL_LOW=1
declare -r THREAT_LEVEL_MEDIUM=2
declare -r THREAT_LEVEL_HIGH=3
declare -r THREAT_LEVEL_CRITICAL=4

# Threat level names
declare -A THREAT_LEVEL_NAMES=(
    [$THREAT_LEVEL_NONE]="NONE"
    [$THREAT_LEVEL_LOW]="LOW"
    [$THREAT_LEVEL_MEDIUM]="MEDIUM"
    [$THREAT_LEVEL_HIGH]="HIGH"
    [$THREAT_LEVEL_CRITICAL]="CRITICAL"
)

# Threat level colors
declare -A THREAT_LEVEL_DISPLAY=(
    [$THREAT_LEVEL_NONE]="${COLOR_THREAT_NONE}NONE${NC}"
    [$THREAT_LEVEL_LOW]="${COLOR_THREAT_LOW}LOW${NC}"
    [$THREAT_LEVEL_MEDIUM]="${COLOR_THREAT_MEDIUM}MEDIUM${NC}"
    [$THREAT_LEVEL_HIGH]="${COLOR_THREAT_HIGH}HIGH${NC}"
    [$THREAT_LEVEL_CRITICAL]="${COLOR_THREAT_CRITICAL}CRITICAL${NC}"
)

# High-risk countries (state-sponsored threat actors)
declare -a HIGH_RISK_COUNTRIES=("CN" "RU" "KP" "IR" "SY")
declare -a MEDIUM_RISK_COUNTRIES=("BY" "VE" "CU" "PK" "MM")

# Known malicious port patterns
declare -a SUSPICIOUS_PORTS=(
    4444    # Metasploit default
    31337   # Elite backdoor
    12345   # NetBus trojan
    27374   # SubSeven trojan
    1234    # Common malware
    5555    # Android ADB
    6666    # IRC bot
    6667    # IRC
    31337   # Elite
)

# Threat scoring function
calculate_threat_score() {
    local ip="$1"
    local port="${2:-0}"
    local country="${3:-UNK}"
    local asn="${4:-}"
    
    local score=0
    local reasons=()
    
    # Country-based risk
    if [[ " ${HIGH_RISK_COUNTRIES[*]} " =~ " $country " ]]; then
        ((score += 30))
        reasons+=("High-risk country: $country")
    elif [[ " ${MEDIUM_RISK_COUNTRIES[*]} " =~ " $country " ]]; then
        ((score += 15))
        reasons+=("Medium-risk country: $country")
    fi
    
    # Port-based risk
    for suspicious_port in "${SUSPICIOUS_PORTS[@]}"; do
        if [[ $port -eq $suspicious_port ]]; then
            ((score += 25))
            reasons+=("Suspicious port: $port")
            break
        fi
    done
    
    # Known high-risk ports
    local port_risk
    port_risk=$(get_port_risk "$port")
    case "$port_risk" in
        CRITICAL)
            ((score += 20))
            reasons+=("Critical risk port: $port ($(get_port_service "$port"))")
            ;;
        HIGH)
            ((score += 10))
            ;;
    esac
    
    # ASN-based risk
    for bulletproof_asn in ${THREAT_INDICATORS["BULLETPROOF_HOSTING"]}; do
        if [[ "$asn" == "$bulletproof_asn" ]]; then
            ((score += 40))
            reasons+=("Bulletproof hosting: $asn")
            break
        fi
    done
    
    # Determine threat level
    local level=$THREAT_LEVEL_NONE
    if [[ $score -ge 60 ]]; then
        level=$THREAT_LEVEL_CRITICAL
    elif [[ $score -ge 40 ]]; then
        level=$THREAT_LEVEL_HIGH
    elif [[ $score -ge 20 ]]; then
        level=$THREAT_LEVEL_MEDIUM
    elif [[ $score -ge 10 ]]; then
        level=$THREAT_LEVEL_LOW
    fi
    
    echo "$level|$score|${reasons[*]}"
}

# Check IP against threat intelligence feeds
check_threat_intel() {
    local ip="$1"
    local threats=()
    
    # Check against various threat feeds (placeholder for actual feed integration)
    # In production, this would query actual threat intelligence APIs
    
    # Return threat assessment
    if [[ ${#threats[@]} -gt 0 ]]; then
        echo "THREAT|${threats[*]}"
    else
        echo "CLEAN"
    fi
}

# ==============================================================================
# MODULE 7.3: DNS RESOLUTION FUNCTIONS
# ==============================================================================

# DNS cache
declare -gA DNS_CACHE=()
declare -gA DNS_CACHE_TIMESTAMPS=()

# Reverse DNS lookup
reverse_dns_lookup() {
    local ip="$1"
    local cache_key="$ip"
    local current_time
    current_time=$(date +%s)
    
    # Check cache
    if [[ -n "${DNS_CACHE[$cache_key]:-}" ]]; then
        local cache_time="${DNS_CACHE_TIMESTAMPS[$cache_key]:-0}"
        local age=$((current_time - cache_time))
        
        if [[ $age -lt 3600 ]]; then  # 1 hour cache
            echo "${DNS_CACHE[$cache_key]}"
            return 0
        fi
    fi
    
    # Perform reverse lookup
    local hostname
    hostname=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
    
    if [[ -z "$hostname" ]]; then
        hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
    fi
    
    hostname="${hostname:-$ip}"
    
    # Cache result
    DNS_CACHE[$cache_key]="$hostname"
    DNS_CACHE_TIMESTAMPS[$cache_key]=$current_time
    
    echo "$hostname"
}

# Forward DNS lookup
forward_dns_lookup() {
    local hostname="$1"
    
    local ip
    ip=$(dig +short "$hostname" A 2>/dev/null | head -1)
    
    if [[ -z "$ip" ]]; then
        ip=$(host "$hostname" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
    fi
    
    echo "${ip:-Unknown}"
}

# ==============================================================================
# MODULE 7.4: WHOIS LOOKUP FUNCTIONS
# ==============================================================================

# WHOIS cache
declare -gA WHOIS_CACHE=()

# Perform WHOIS lookup
whois_lookup() {
    local target="$1"
    local cache_key="$target"
    
    # Check cache
    if [[ -n "${WHOIS_CACHE[$cache_key]:-}" ]]; then
        echo "${WHOIS_CACHE[$cache_key]}"
        return 0
    fi
    
    local result
    result=$(whois "$target" 2>/dev/null | head -50)
    
    if [[ -n "$result" ]]; then
        WHOIS_CACHE[$cache_key]="$result"
    fi
    
    echo "$result"
}

# Extract organization from WHOIS
extract_whois_org() {
    local whois_data="$1"
    
    local org
    org=$(echo "$whois_data" | grep -iE "^(org-name|organization|orgname|owner):" | head -1 | cut -d':' -f2- | xargs)
    
    echo "${org:-Unknown}"
}

# Extract country from WHOIS
extract_whois_country() {
    local whois_data="$1"
    
    local country
    country=$(echo "$whois_data" | grep -iE "^country:" | head -1 | awk '{print $2}')
    
    echo "${country:-UNK}"
}


# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 8: PACKET CAPTURE AND ANALYSIS ENGINE                        ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 8.1: TCPDUMP WRAPPER FUNCTIONS
# ==============================================================================

# Start packet capture
start_packet_capture() {
    local interface="${1:-$EXTIPMON_INTERFACE}"
    local filter="${2:-$EXTIPMON_CAPTURE_FILTER}"
    local pcap_file="${3:-$EXTIPMON_PCAP_FILE}"
    
    log_info "Starting packet capture on interface: $interface"
    
    # Build tcpdump command
    local tcpdump_cmd="tcpdump"
    local tcpdump_args=("-i" "$interface" "-n" "-l" "-q" "-tttt")
    
    # Add promiscuous mode if enabled
    if [[ $EXTIPMON_PROMISCUOUS -eq 1 ]]; then
        tcpdump_args+=("-p")
    fi
    
    # Add snapshot length
    tcpdump_args+=("-s" "$EXTIPMON_SNAPSHOT_LENGTH")
    
    # Add buffer size
    tcpdump_args+=("-B" "$((EXTIPMON_BUFFER_SIZE / 1024))")
    
    # Add pcap output
    if [[ -n "$pcap_file" ]]; then
        tcpdump_args+=("-w" "$pcap_file")
    fi
    
    # Add filter if specified
    if [[ -n "$filter" ]]; then
        tcpdump_args+=("$filter")
    fi
    
    # Start tcpdump
    $tcpdump_cmd "${tcpdump_args[@]}" 2>/dev/null &
    EXTIPMON_TCPDUMP_PID=$!
    
    log_info "Packet capture started with PID: $EXTIPMON_TCPDUMP_PID"
    
    return 0
}

# Stop packet capture
stop_packet_capture() {
    if [[ -n "${EXTIPMON_TCPDUMP_PID:-}" ]]; then
        log_info "Stopping packet capture (PID: $EXTIPMON_TCPDUMP_PID)"
        kill -TERM "$EXTIPMON_TCPDUMP_PID" 2>/dev/null
        wait "$EXTIPMON_TCPDUMP_PID" 2>/dev/null
        EXTIPMON_TCPDUMP_PID=""
    fi
    
    # Also kill any stray tcpdump processes
    pkill -f "tcpdump.*$EXTIPMON_SESSION_ID" 2>/dev/null
    
    log_info "Packet capture stopped"
}

# Parse tcpdump output line
parse_tcpdump_line() {
    local line="$1"
    
    # Extract timestamp
    local timestamp
    timestamp=$(echo "$line" | awk '{print $1" "$2}')
    
    # Extract source IP and port
    local src_full
    src_full=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local src_ip="${src_full%.*}"
    local src_port="${src_full##*.}"
    
    # Extract destination IP and port
    local dst_full
    dst_full=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
    local dst_ip="${dst_full%.*}"
    local dst_port="${dst_full##*.}"
    
    # Determine protocol
    local protocol="TCP"
    if [[ "$line" == *"UDP"* ]]; then
        protocol="UDP"
    elif [[ "$line" == *"ICMP"* ]]; then
        protocol="ICMP"
    fi
    
    # Extract packet length
    local length
    length=$(echo "$line" | grep -oE 'length [0-9]+' | awk '{print $2}')
    length="${length:-0}"
    
    echo "$timestamp|$src_ip|$src_port|$dst_ip|$dst_port|$protocol|$length"
}

# ==============================================================================
# MODULE 8.2: NETSTAT AND SS WRAPPER FUNCTIONS
# ==============================================================================

# Get current connections using netstat
get_connections_netstat() {
    local filter="${1:-all}"
    
    local netstat_output
    netstat_output=$(netstat -an 2>/dev/null | grep -E "^(tcp|udp)")
    
    case "$filter" in
        established)
            echo "$netstat_output" | grep "ESTABLISHED"
            ;;
        listening)
            echo "$netstat_output" | grep "LISTEN"
            ;;
        all)
            echo "$netstat_output"
            ;;
    esac
}

# Get current connections using ss (preferred on Linux)
get_connections_ss() {
    local filter="${1:-all}"
    
    case "$filter" in
        established)
            ss -tun state established 2>/dev/null
            ;;
        listening)
            ss -tun state listening 2>/dev/null
            ;;
        all)
            ss -tuna 2>/dev/null
            ;;
    esac
}

# Get external connections only
get_external_connections() {
    local connections
    
    # On macOS, netstat output format is different - use lsof for better results
    if [[ "$(uname)" == "Darwin" ]]; then
        # Use lsof to get all network connections on macOS
        connections=$(lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|UDP" | grep -v "localhost")
    elif command -v ss &>/dev/null; then
        connections=$(get_connections_ss "established")
    else
        connections=$(get_connections_netstat "established")
    fi
    
    # Filter to external IPs only
    echo "$connections" | while read -r line; do
        # Extract remote IP - handle both netstat and lsof formats
        local remote_ip
        remote_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
        
        if [[ -n "$remote_ip" ]] && is_external_ip "$remote_ip"; then
            echo "$line"
        fi
    done
}

# Get ALL connections including from packet capture
get_all_live_connections() {
    local interface="${1:-any}"
    local duration="${2:-1}"
    
    # Capture packets briefly to detect connections
    local temp_output="/tmp/extipmon_capture_$$"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS tcpdump
        sudo tcpdump -i "$interface" -n -c 500 -q 2>/dev/null | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
            sort -u > "$temp_output" &
    else
        # Linux tcpdump
        sudo tcpdump -i "$interface" -n -c 500 -q 2>/dev/null | \
            grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
            sort -u > "$temp_output" &
    fi
    
    local tcpdump_pid=$!
    sleep "$duration"
    kill "$tcpdump_pid" 2>/dev/null
    wait "$tcpdump_pid" 2>/dev/null
    
    # Read captured IPs
    if [[ -f "$temp_output" ]]; then
        cat "$temp_output"
        rm -f "$temp_output"
    fi
}

# ==============================================================================
# MODULE 8.3: INTERFACE DETECTION AND MANAGEMENT
# ==============================================================================

# Get list of network interfaces
get_network_interfaces() {
    local active_only="${1:-1}"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS - use ifconfig -l to list all interfaces
        if [[ $active_only -eq 1 ]]; then
            # Get active interfaces (those with inet addresses)
            for iface in $(ifconfig -l 2>/dev/null); do
                if ifconfig "$iface" 2>/dev/null | grep -q "inet "; then
                    echo "$iface"
                fi
            done
        else
            # List all interfaces
            ifconfig -l 2>/dev/null | tr ' ' '\n'
        fi
    else
        # Linux
        if [[ $active_only -eq 1 ]]; then
            ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1
        else
            ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1
        fi
    fi
}

# List and display available interfaces
list_interfaces() {
    echo -e "${CLR256_CYAN}[*] Available network interfaces:${NC}"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        for iface in $(ifconfig -l 2>/dev/null); do
            local ip_addr
            ip_addr=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
            if [[ -n "$ip_addr" ]]; then
                echo -e "    ${CLR256_GREEN}${ICON_CONNECTED}${NC} $iface ($ip_addr)"
            else
                echo -e "    ${CLR256_GRAY_12}${ICON_DISCONNECTED}${NC} $iface"
            fi
        done
    else
        # Linux
        ip -o link show 2>/dev/null | while read -r line; do
            local iface
            iface=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
            local state
            state=$(echo "$line" | grep -o "state [A-Z]*" | awk '{print $2}')
            local ip_addr
            ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
            
            if [[ "$state" == "UP" ]] && [[ -n "$ip_addr" ]]; then
                echo -e "    ${CLR256_GREEN}${ICON_CONNECTED}${NC} $iface ($ip_addr)"
            else
                echo -e "    ${CLR256_GRAY_12}${ICON_DISCONNECTED}${NC} $iface"
            fi
        done
    fi
}

# Get primary interface
get_primary_interface() {
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS - get the interface with default route
        route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}'
    else
        # Linux
        ip route show default 2>/dev/null | awk '{print $5}' | head -1
    fi
}

# Get interface IP address
get_interface_ip() {
    local interface="$1"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        ifconfig "$interface" 2>/dev/null | grep "inet " | awk '{print $2}'
    else
        ip -4 addr show "$interface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d'/' -f1
    fi
}

# Get interface MAC address
get_interface_mac() {
    local interface="$1"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        ifconfig "$interface" 2>/dev/null | grep "ether " | awk '{print $2}'
    else
        ip link show "$interface" 2>/dev/null | grep "link/ether" | awk '{print $2}'
    fi
}

# ==============================================================================
# MODULE 8.4: BANDWIDTH MONITORING
# ==============================================================================

# Interface traffic statistics
declare -gA INTERFACE_RX_BYTES=()
declare -gA INTERFACE_TX_BYTES=()
declare -gA INTERFACE_RX_PACKETS=()
declare -gA INTERFACE_TX_PACKETS=()
declare -gA INTERFACE_LAST_UPDATE=()

# Get interface statistics
get_interface_stats() {
    local interface="$1"
    
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        local stats
        stats=$(netstat -I "$interface" -b 2>/dev/null | tail -1)
        local rx_bytes tx_bytes rx_packets tx_packets
        rx_bytes=$(echo "$stats" | awk '{print $7}')
        tx_bytes=$(echo "$stats" | awk '{print $10}')
        rx_packets=$(echo "$stats" | awk '{print $5}')
        tx_packets=$(echo "$stats" | awk '{print $8}')
        echo "$rx_bytes|$tx_bytes|$rx_packets|$tx_packets"
    else
        # Linux
        if [[ -f "/sys/class/net/$interface/statistics/rx_bytes" ]]; then
            local rx_bytes tx_bytes rx_packets tx_packets
            rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes" 2>/dev/null)
            tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null)
            rx_packets=$(cat "/sys/class/net/$interface/statistics/rx_packets" 2>/dev/null)
            tx_packets=$(cat "/sys/class/net/$interface/statistics/tx_packets" 2>/dev/null)
            echo "$rx_bytes|$tx_bytes|$rx_packets|$tx_packets"
        else
            echo "0|0|0|0"
        fi
    fi
}

# Calculate bandwidth rate
calculate_bandwidth() {
    local interface="$1"
    local current_time
    current_time=$(date +%s)
    
    # Get current stats
    local stats
    stats=$(get_interface_stats "$interface")
    local IFS='|'
    read -ra current <<< "$stats"
    
    local rx_bytes="${current[0]:-0}"
    local tx_bytes="${current[1]:-0}"
    
    # Get previous stats
    local prev_rx="${INTERFACE_RX_BYTES[$interface]:-$rx_bytes}"
    local prev_tx="${INTERFACE_TX_BYTES[$interface]:-$tx_bytes}"
    local prev_time="${INTERFACE_LAST_UPDATE[$interface]:-$current_time}"
    
    # Calculate rate
    local time_diff=$((current_time - prev_time))
    if [[ $time_diff -gt 0 ]]; then
        local rx_rate=$(( (rx_bytes - prev_rx) / time_diff ))
        local tx_rate=$(( (tx_bytes - prev_tx) / time_diff ))
    else
        local rx_rate=0
        local tx_rate=0
    fi
    
    # Update stored values
    INTERFACE_RX_BYTES[$interface]=$rx_bytes
    INTERFACE_TX_BYTES[$interface]=$tx_bytes
    INTERFACE_LAST_UPDATE[$interface]=$current_time
    
    echo "$rx_rate|$tx_rate"
}

# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 9: UI AND DISPLAY FUNCTIONS                                  ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 9.1: TERMINAL CONTROL FUNCTIONS
# ==============================================================================

# Clear screen
clear_screen() {
    printf '\033[2J\033[H'
}

# Move cursor to position
move_cursor() {
    local row="$1"
    local col="$2"
    printf '\033[%d;%dH' "$row" "$col"
}

# Hide cursor
hide_cursor() {
    printf '\033[?25l'
}

# Show cursor
show_cursor() {
    printf '\033[?25h'
}

# Save cursor position
save_cursor() {
    printf '\033[s'
}

# Restore cursor position
restore_cursor() {
    printf '\033[u'
}

# Clear line
clear_line() {
    printf '\033[2K'
}

# Clear to end of line
clear_to_eol() {
    printf '\033[K'
}

# Set terminal title
set_terminal_title() {
    local title="$1"
    printf '\033]0;%s\007' "$title"
}

# Get terminal size
update_terminal_size() {
    EXTIPMON_TERM_ROWS=$(tput lines 2>/dev/null || echo 24)
    EXTIPMON_TERM_COLS=$(tput cols 2>/dev/null || echo 80)
}

# ==============================================================================
# MODULE 9.2: BANNER AND HEADER DISPLAY
# ==============================================================================

# Display main banner
display_banner() {
    clear_screen
    
    echo -e "${CLR256_SAPPHIRE}"
    cat << 'BANNER'
███████╗██╗  ██╗████████╗    ██╗██████╗     ███╗   ███╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗██╔╝╚══██╔══╝    ██║██╔══██╗    ████╗ ████║██╔═══██╗████╗  ██║
█████╗   ╚███╔╝    ██║       ██║██████╔╝    ██╔████╔██║██║   ██║██╔██╗ ██║
██╔══╝   ██╔██╗    ██║       ██║██╔═══╝     ██║╚██╔╝██║██║   ██║██║╚██╗██║
███████╗██╔╝ ██╗   ██║       ██║██║         ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝╚═╝         ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
BANNER
    echo -e "${NC}"
    
    echo -e "${CLR256_GRAY_12}    EXTERNAL IP CONNECTION MONITOR v${EXTIPMON_VERSION}${NC}"
    echo -e "${CLR256_GRAY_8}    Real-time monitoring of all external & active connections${NC}"
    echo ""
    print_separator
}

# Display status header
display_status_header() {
    local current_time
    current_time=$(date '+%Y-%m-%d %H:%M:%S')
    local uptime
    uptime=$(format_duration $(($(date +%s) - EXTIPMON_SESSION_START)))
    
    move_cursor 1 1
    echo -e "${CLR256_BG_DARK_GRAY}${CLR256_WHITE}${CLR_BOLD} EXTIPMON ${NC}${CLR256_BG_DARK_GRAY} | Time: ${current_time} | Uptime: ${uptime} | Active: ${ACTIVE_CONNECTION_COUNT} | Total: ${TOTAL_CONNECTIONS} ${NC}"
}

# Display connection table header
display_table_header() {
    echo -e "${CLR256_BG_DARK_GRAY}${CLR256_WHITE}${CLR_BOLD}"
    printf "%-18s %-6s %-8s %-20s %-15s %-10s %-12s\n" \
        "IP ADDRESS" "PORT" "PROTO" "LOCATION" "DURATION" "BYTES" "STATUS"
    echo -e "${NC}"
    print_separator 80 "─"
}

# ==============================================================================
# MODULE 9.3: CONNECTION DISPLAY FUNCTIONS
# ==============================================================================

# Display a single connection
display_connection() {
    local ip="$1"
    local port="$2"
    local protocol="$3"
    local country="$4"
    local city="$5"
    local duration="$6"
    local bytes="$7"
    local status="$8"
    local threat_level="${9:-0}"
    
    local flag
    flag=$(get_country_flag "$country")
    
    local location
    if [[ -n "$city" ]] && [[ "$city" != "Unknown" ]]; then
        location="$flag $city, $country"
    else
        location="$flag $country"
    fi
    location=$(truncate "$location" 18)
    
    local formatted_duration
    formatted_duration=$(format_duration "$duration")
    
    local formatted_bytes
    formatted_bytes=$(format_bytes "$bytes")
    
    # Color based on status and threat level
    local status_color="$COLOR_ACTIVE"
    case "$status" in
        ESTABLISHED|ACTIVE) status_color="$COLOR_CONNECTED" ;;
        IDLE) status_color="$COLOR_IDLE" ;;
        CLOSING|TIMEOUT) status_color="$COLOR_DISCONNECTED" ;;
    esac
    
    local threat_color="${COLOR_THREAT_NONE}"
    case "$threat_level" in
        1) threat_color="$COLOR_THREAT_LOW" ;;
        2) threat_color="$COLOR_THREAT_MEDIUM" ;;
        3) threat_color="$COLOR_THREAT_HIGH" ;;
        4) threat_color="$COLOR_THREAT_CRITICAL" ;;
    esac
    
    printf "${CLR256_WHITE}%-18s${NC} ${CLR256_CYAN}%-6s${NC} ${CLR256_YELLOW}%-8s${NC} %-20s ${CLR256_GREEN}%-15s${NC} ${CLR256_ORANGE}%-10s${NC} ${status_color}%-12s${NC}\n" \
        "$ip" "$port" "$protocol" "$location" "$formatted_duration" "$formatted_bytes" "$status"
}

# Display all active connections
display_active_connections() {
    local max_display="${1:-$EXTIPMON_MAX_DISPLAY_CONNECTIONS}"
    local current_time
    current_time=$(date +%s)
    
    display_table_header
    
    local count=0
    for key in "${!ACTIVE_CONNECTIONS[@]}"; do
        if [[ $count -ge $max_display ]]; then
            break
        fi
        
        local ip="${key%%:*}"
        local rest="${key#*:}"
        local port="${rest%%:*}"
        local protocol="${rest##*:}"
        
        # Skip internal IPs if configured
        if [[ $EXTIPMON_SHOW_INTERNAL -eq 0 ]] && ! is_external_ip "$ip"; then
            continue
        fi
        
        local start_time="${CONNECTION_START_TIMES[$key]:-$current_time}"
        local duration=$((current_time - start_time))
        local bytes=$((${CONNECTION_BYTES_IN[$key]:-0} + ${CONNECTION_BYTES_OUT[$key]:-0}))
        local state="${CONNECTION_STATES[$key]:-UNKNOWN}"
        local country="${CONNECTION_GEO_COUNTRY[$key]:-UNK}"
        local city="${CONNECTION_GEO_CITY[$key]:-}"
        local threat="${CONNECTION_THREAT_LEVELS[$key]:-0}"
        
        display_connection "$ip" "$port" "$protocol" "$country" "$city" "$duration" "$bytes" "$state" "$threat"
        
        ((count++))
    done
    
    if [[ $count -eq 0 ]]; then
        echo -e "${CLR256_GRAY_12}  No active external connections${NC}"
    fi
    
    if [[ ${#ACTIVE_CONNECTIONS[@]} -gt $max_display ]]; then
        echo -e "${CLR256_GRAY_8}  ... and $((${#ACTIVE_CONNECTIONS[@]} - max_display)) more connections${NC}"
    fi
}

# Display recent disconnections
display_recent_disconnections() {
    local max_display="${1:-10}"
    
    echo ""
    echo -e "${CLR256_ORANGE}${CLR_BOLD}Recent Disconnections:${NC}"
    print_separator 80 "─"
    
    local count=0
    for key in "${!DISCONNECTION_TIMES[@]}"; do
        if [[ $count -ge $max_display ]]; then
            break
        fi
        
        local ip="${key%%:*}"
        local rest="${key#*:}"
        local port="${rest%%:*}"
        
        local disconnect_time="${DISCONNECTION_TIMES[$key]:-0}"
        local duration="${DISCONNECTION_DURATIONS[$key]:-0}"
        
        local formatted_time
        formatted_time=$(date -d "@$disconnect_time" '+%H:%M:%S' 2>/dev/null || date -r "$disconnect_time" '+%H:%M:%S' 2>/dev/null)
        local formatted_duration
        formatted_duration=$(format_duration "$duration")
        
        echo -e "${COLOR_DISCONNECTED}${ICON_DISCONNECTED}${NC} ${CLR256_WHITE}$ip:$port${NC} - Disconnected at ${CLR256_YELLOW}$formatted_time${NC} (was connected for $formatted_duration)"
        
        ((count++))
    done
    
    if [[ $count -eq 0 ]]; then
        echo -e "${CLR256_GRAY_12}  No recent disconnections${NC}"
    fi
}

# Display statistics summary
display_statistics() {
    echo ""
    echo -e "${CLR256_CYAN}${CLR_BOLD}Session Statistics:${NC}"
    print_separator 80 "─"
    
    local bytes_in_formatted
    bytes_in_formatted=$(format_bytes "$TOTAL_BYTES_IN")
    local bytes_out_formatted
    bytes_out_formatted=$(format_bytes "$TOTAL_BYTES_OUT")
    local uptime
    uptime=$(format_duration $(($(date +%s) - EXTIPMON_SESSION_START)))
    
    echo -e "  Active Connections:  ${CLR256_GREEN}${ACTIVE_CONNECTION_COUNT}${NC}"
    echo -e "  Total Connections:   ${CLR256_WHITE}${TOTAL_CONNECTIONS}${NC}"
    echo -e "  Total Disconnections:${CLR256_ORANGE}${TOTAL_DISCONNECTIONS}${NC}"
    echo -e "  Data Received:       ${CLR256_SAPPHIRE}${bytes_in_formatted}${NC}"
    echo -e "  Data Sent:           ${CLR256_YELLOW}${bytes_out_formatted}${NC}"
    echo -e "  Packets In:          ${CLR256_WHITE}$(format_number "$TOTAL_PACKETS_IN")${NC}"
    echo -e "  Packets Out:         ${CLR256_WHITE}$(format_number "$TOTAL_PACKETS_OUT")${NC}"
    echo -e "  Session Uptime:      ${CLR256_CYAN}${uptime}${NC}"
}

# ==============================================================================
# MODULE 9.4: MAIN DISPLAY LOOP
# ==============================================================================

# Main UI refresh function
refresh_display() {
    update_terminal_size
    
    # Check for timed out connections
    check_connection_timeouts
    
    # Clear and redraw
    clear_screen
    display_banner
    display_status_header
    echo ""
    display_active_connections
    display_recent_disconnections 5
    display_statistics
    
    # Footer
    echo ""
    print_separator
    echo -e "${CLR256_GRAY_8}Press Ctrl+C to stop monitoring${NC}"
}


# ##############################################################################
# ##############################################################################
# ##                                                                          ##
# ##    SECTION 10: MAIN ENTRY POINT AND ORIGINAL TITAN NET MONITOR CODE     ##
# ##                                                                          ##
# ##############################################################################
# ##############################################################################

# ==============================================================================
# MODULE 10.1: SIGNAL HANDLING AND CLEANUP
# ==============================================================================

# Cleanup function
cleanup() {
    # Only run cleanup once
    if [[ -f "/tmp/extipmon_cleanup.lock" ]]; then return; fi
    touch "/tmp/extipmon_cleanup.lock"

    # Reset cursor and terminal
    show_cursor
    echo -e "${NC}"
    
    # Stop packet capture
    stop_packet_capture
    
    # Kill Python Engine if running
    if [[ -n "${EXTIPMON_ENGINE_PID:-}" ]]; then
        log_info "Stopping Analysis Engine (PID: $EXTIPMON_ENGINE_PID)"
        kill -TERM "$EXTIPMON_ENGINE_PID" 2>/dev/null
        wait "$EXTIPMON_ENGINE_PID" 2>/dev/null
    fi
    
    # Clean temporary files
    rm -f "/tmp/extipmon_cleanup.lock"
    rm -rf "$EXTIPMON_TEMP_DIR"
    
    echo -e "${COLOR_SUCCESS}[✓] Session Saved:${NC}"
    echo -e "    ├── PCAP: ${CLR256_WHITE}${EXTIPMON_PCAP_FILE}${NC}"
    echo -e "    ├── Events: ${CLR256_WHITE}${EXTIPMON_EVENT_LOG}${NC}"
    echo -e "    └── Connections: ${CLR256_WHITE}${EXTIPMON_CONNECTION_LOG}${NC}"
    echo -e "${COLOR_SUCCESS}[✓] ExtIPMon System Halted.${NC}"
    
    # Clean up FIFO
    rm -f "/tmp/extipmon_fifo_$$" 2>/dev/null
    rm -f /tmp/extipmon_fifo_* 2>/dev/null
    rm -f /tmp/extipmon_capture_* 2>/dev/null
    
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM EXIT

# ==============================================================================
# MODULE 10.2: DEPENDENCY AND SYSTEM CHECKS
# ==============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${COLOR_ERROR}[!] Error: This script requires root privileges for packet capture.${NC}"
        echo -e "${COLOR_WARNING}[*] Please run with: sudo $0${NC}"
        exit 1
    fi
}

check_dependencies() {
    log_info "Verifying Environment..."

    # Check Architecture
    local arch
    arch=$(uname -m)
    if [[ "$arch" == "arm64" ]]; then
        print_success "Detected Apple Silicon (M1/M2/M3)"
    elif [[ "$arch" == "x86_64" ]]; then
        print_success "Detected x86_64 Architecture"
    else
        print_warning "Running on $arch (Non-standard)"
    fi

    # Check TCPDUMP
    if ! command -v tcpdump &> /dev/null; then
        print_error "Critical: tcpdump not found."
        exit 1
    fi
    print_success "tcpdump available"

    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        print_error "Critical: python3 not found."
        exit 1
    fi
    print_success "python3 available"

    # Create Directories
    mkdir -p "$EXTIPMON_PCAP_DIR" "$EXTIPMON_LOG_DIR" "$EXTIPMON_DATA_DIR" "$EXTIPMON_CACHE_DIR" "$EXTIPMON_TEMP_DIR"
    touch "$EXTIPMON_DEBUG_LOG" "$EXTIPMON_EVENT_LOG" "$EXTIPMON_CONNECTION_LOG"
    
    print_success "Directory structure created"
}

# ==============================================================================
# MODULE 10.3: MAIN MONITORING LOOP
# ==============================================================================

# Process a connection event from the monitoring subsystem
process_connection_event() {
    local event_type="$1"
    local ip="$2"
    local port="${3:-0}"
    local protocol="${4:-TCP}"
    local bytes="${5:-0}"
    
    case "$event_type" in
        NEW|CONNECT)
            register_connection "$ip" "$port" "$protocol" "IN"
            
            # Lookup GeoIP info asynchronously
            if [[ $EXTIPMON_GEOIP_ENABLED -eq 1 ]] && is_external_ip "$ip"; then
                local geoip_result
                geoip_result=$(lookup_geoip "$ip")
                local IFS='|'
                read -ra geo_parts <<< "$geoip_result"
                
                local key
                key=$(generate_connection_key "$ip" "$port" "$protocol")
                CONNECTION_GEO_COUNTRY[$key]="${geo_parts[0]:-UNK}"
                CONNECTION_GEO_CITY[$key]="${geo_parts[1]:-}"
            fi
            ;;
        UPDATE|DATA)
            update_connection "$ip" "$port" "$protocol" "$bytes" 0 1
            ;;
        CLOSE|DISCONNECT)
            unregister_connection "$ip" "$port" "$protocol"
            ;;
    esac
}

# Main monitoring function
run_monitor() {
    log_info "Starting External IP Monitor"
    
    # Initialize connection tracking
    init_connection_tracking
    
    # List available interfaces
    echo ""
    list_interfaces
    echo ""
    
    # Determine interface to use
    local capture_interface="${EXTIPMON_INTERFACE:-any}"
    if [[ "$capture_interface" == "any" ]]; then
        # Try to get primary interface
        local primary
        primary=$(get_primary_interface)
        if [[ -n "$primary" ]]; then
            print_info "Primary interface detected: $primary"
        fi
    fi
    
    print_info "Monitoring interface: $capture_interface"
    print_info "Starting live packet capture..."
    echo ""
    
    # Start packet capture in background
    start_packet_capture "$capture_interface"
    
    # Hide cursor for cleaner display
    hide_cursor
    
    # Set terminal title
    set_terminal_title "ExtIPMon - External IP Monitor"
    
    # Start tcpdump and parse output in real-time
    local tcpdump_fifo="/tmp/extipmon_fifo_$$"
    mkfifo "$tcpdump_fifo" 2>/dev/null
    
    # Start tcpdump and redirect to FIFO
    (
        sudo tcpdump -i "$capture_interface" -n -l -q 2>/dev/null | while read -r line; do
            echo "$line"
        done
    ) > "$tcpdump_fifo" &
    local tcpdump_reader_pid=$!
    
    # Process tcpdump output in background
    (
        while read -r line; do
            # Extract IPs from tcpdump output
            local src_ip dst_ip
            src_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            dst_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
            
            # Extract ports
            local src_port dst_port
            src_port=$(echo "$line" | grep -oE '\.[0-9]+:' | head -1 | tr -d '.:' | tail -c 6)
            dst_port=$(echo "$line" | grep -oE '\.[0-9]+:' | tail -1 | tr -d '.:' | tail -c 6)
            
            # Determine protocol
            local protocol="TCP"
            if echo "$line" | grep -qi "UDP"; then
                protocol="UDP"
            elif echo "$line" | grep -qi "ICMP"; then
                protocol="ICMP"
            fi
            
            # Process external IPs
            if [[ -n "$src_ip" ]] && is_external_ip "$src_ip"; then
                process_connection_event "UPDATE" "$src_ip" "${src_port:-0}" "$protocol" 0
            fi
            if [[ -n "$dst_ip" ]] && [[ "$dst_ip" != "$src_ip" ]] && is_external_ip "$dst_ip"; then
                process_connection_event "UPDATE" "$dst_ip" "${dst_port:-0}" "$protocol" 0
            fi
        done < "$tcpdump_fifo"
    ) &
    local processor_pid=$!
    
    # Also monitor using lsof/netstat for established connections
    local last_refresh=0
    local refresh_interval=1  # Refresh every second
    
    while true; do
        local current_time
        current_time=$(date +%s)
        
        # Get current connections from system (netstat/lsof)
        local connections
        connections=$(get_external_connections)
        
        # Process each connection
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            
            # Extract IP from connection line
            local remote_ip
            remote_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
            
            local remote_port
            remote_port=$(echo "$line" | grep -oE ':[0-9]+' | tail -1 | tr -d ':')
            
            if [[ -n "$remote_ip" ]] && is_external_ip "$remote_ip"; then
                process_connection_event "UPDATE" "$remote_ip" "${remote_port:-0}" "TCP" 0
            fi
        done <<< "$connections"
        
        # Refresh display periodically
        if [[ $((current_time - last_refresh)) -ge $refresh_interval ]]; then
            refresh_display
            last_refresh=$current_time
        fi
        
        # Small sleep to prevent CPU spinning
        sleep 0.1
    done
}

# ==============================================================================
# MODULE 10.4: COMMAND LINE INTERFACE
# ==============================================================================

show_help() {
    cat << EOF
ExtIPMon - External IP Connection Monitor v${EXTIPMON_VERSION}

USAGE:
    sudo $0 [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    -v, --version       Show version information
    -i, --interface     Specify network interface (default: any)
    -q, --quiet         Suppress console output
    -d, --debug         Enable debug mode
    --no-geoip          Disable GeoIP lookups
    --no-color          Disable colored output

DESCRIPTION:
    Monitors all external IP connections in real-time, displaying:
    - "X IP Connected at X-time - (live connection timer)"
    - "X IP Disconnected at X-time - (time it disconnected)"
    
    Tracks all ports and protocols for complete network visibility.

EXAMPLES:
    sudo $0                     # Start monitoring on all interfaces
    sudo $0 -i en0              # Monitor specific interface
    sudo $0 --debug             # Enable debug logging

EOF
}

show_version() {
    echo "ExtIPMon v${EXTIPMON_VERSION}"
    echo "Build Date: ${EXTIPMON_BUILD_DATE}"
    echo "Author: ${EXTIPMON_AUTHOR}"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -i|--interface)
                EXTIPMON_INTERFACE="$2"
                shift 2
                ;;
            -q|--quiet)
                EXTIPMON_QUIET=1
                shift
                ;;
            -d|--debug)
                EXTIPMON_DEBUG_MODE=1
                CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG
                shift
                ;;
            --no-geoip)
                EXTIPMON_GEOIP_ENABLED=0
                shift
                ;;
            --no-color)
                EXTIPMON_COLOR_OUTPUT=0
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ==============================================================================
# MODULE 10.5: MAIN ENTRY POINT
# ==============================================================================

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check for root privileges
    check_root
    
    # Display banner
    display_banner
    
    # Check dependencies
    check_dependencies
    
    echo ""
    print_info "Starting External IP Monitor..."
    print_info "Interface: ${EXTIPMON_INTERFACE}"
    print_info "GeoIP: $([ $EXTIPMON_GEOIP_ENABLED -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
    echo ""
    
    # Small delay before starting
    sleep 1
    
    # Run the monitor
    run_monitor
}

# Run main function with all arguments
main "$@"
