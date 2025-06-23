#!/bin/bash

# =========================================================================
# sing-box Automatic Smart Share Link Generator
# Compatible with: CentOS/RHEL/Fedora and Arch Linux
# =========================================================================

# Author: logover

# --- Color Definitions ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Function Definitions ---

# Check and automatically install dependencies (cross-platform version)
check_dependencies() {
    local missing_deps=()
    echo "Checking necessary dependencies..."

    # Check common dependencies
    for dep in jq qrencode nginx perl; do
        if ! command -v "$dep" &> /dev/null; then missing_deps+=("$dep"); fi
    done
    # Check dig command
    if ! command -v "dig" &> /dev/null; then
        # dig command is provided by different packages on different distributions
        missing_deps+=("dig_placeholder")
    fi

    if [ ${#missing_deps[@]} -eq 0 ]; then
        echo -e "${GREEN}All dependencies are installed.${NC}"
        return
    fi

    # Detect OS distribution
    local os_id=""
    if [ -f /etc/os-release ]; then
        os_id=$(grep -oP '^ID=\K\w+' /etc/os-release)
    else
        echo -e "${RED}Error: Unable to identify your operating system distribution. Please install dependencies manually.${NC}"
        exit 1
    fi

    local pkg_manager_install=""
    local pkg_manager_update=""
    local dns_pkg_name=""

    # Set package manager and package names based on distribution
    case "$os_id" in
        ubuntu|debian)
            pkg_manager_update="sudo apt-get update"
            pkg_manager_install="sudo apt-get install -y"
            dns_pkg_name="dnsutils"
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                pkg_manager_install="sudo dnf install -y"
            else
                pkg_manager_install="sudo yum install -y"
            fi
            dns_pkg_name="bind-utils"
            ;;
        arch)
            pkg_manager_install="sudo pacman -S --noconfirm"
            dns_pkg_name="bind"
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system distribution: '$os_id'. Please install the following dependencies manually: ${missing_deps[*]}${NC}"
            exit 1
            ;;
    esac

    # Replace placeholder with correct package name
    missing_deps=("${missing_deps[@]/dig_placeholder/$dns_pkg_name}")

    echo -e "${YELLOW}Warning: The following dependencies are not installed: ${missing_deps[*]}${NC}"
    read -p "Do you want to install them automatically? (Y/n) " -n 1 -r REPLY < /dev/tty; echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        echo "Starting installation..."
        # If there's an update command, execute it
        if [[ -n "$pkg_manager_update" ]]; then
            $pkg_manager_update || { echo -e "${RED}Error: Package list update failed.${NC}"; exit 1; }
        fi

        # Install missing packages
        $pkg_manager_install "${missing_deps[@]}" || { echo -e "${RED}Error: Dependency installation failed.${NC}"; exit 1; }

        echo -e "${GREEN}Dependencies installed successfully! Script will continue.${NC}"
    else
        echo -e "${RED}User canceled installation. Exiting.${NC}"; exit 1
    fi
}


find_service_file() {
    local service_name="$1"; local path; path=$(systemctl show -p FragmentPath "${service_name}" 2>/dev/null | cut -d'=' -f2); if [[ -n "$path" && -f "$path" ]]; then echo "$path"; else find /etc/systemd/ /usr/lib/systemd/ -name "${service_name}.service" -print -quit; fi
}
find_singbox_configs() {
    local service_file; service_file=$(find_service_file "sing-box"); if [[ -z "$service_file" ]]; then echo -e "${RED}Error: sing-box.service file not found.${NC}" >&2; return 1; fi; local config_path; config_path=$(grep -oP '(-C|--config)\s+\K(\S+)' "$service_file" | head -n 1); if [[ -z "$config_path" ]]; then config_path="/etc/sing-box/"; fi; if [[ -d "$config_path" ]]; then find "$config_path" -maxdepth 1 -type f -name "*.json"; elif [[ -f "$config_path" ]]; then echo "$config_path"; else echo -e "${RED}Error: No valid configuration path found in ${service_file}.${NC}" >&2; return 1; fi
}
find_nginx_proxies() {
    local conf; conf=$(nginx -T 2>/dev/null); if [ $? -ne 0 ]; then return; fi
    perl -0777 -ne '
        my @server_blocks = split /(?=^\s*server\s*\{)/m, $_;
        foreach my $server_block (@server_blocks) {
            next unless $server_block =~ /^\s*server\s*\{/;
            my $server_name = "localhost"; my $listen_port = "80"; my $is_ssl = "false";
            if ($server_block =~ /^\s*server_name\s+([^;]+)/m) {
                $server_name = $1; $server_name =~ s/^\s+|\s+$//g; $server_name = (split(/\s+/, $server_name))[0];
            }
            my @listen_lines; while ($server_block =~ /^\s*listen\s+([^;]+);/mg) { push @listen_lines, $1; }
            my $found_port = 0;
            foreach my $line (@listen_lines) { if ($line =~ /443/ && $line =~ /ssl/) { $listen_port = "443"; $is_ssl = "true"; $found_port = 1; last; } }
            if (!$found_port && @listen_lines > 0) { if ($listen_lines[0] =~ /(\d+)/) { $listen_port = $1; } if ($listen_lines[0] =~ /ssl/) { $is_ssl = "true"; } }
            my @internal_ports = ($server_block =~ /^\s*proxy_pass\s+http:\/\/(?:127\.0\.0\.1|localhost):(\d+)/mg);
            foreach my $internal_port (@internal_ports) { print "$internal_port;$server_name;$listen_port;$is_ssl\n"; }
        }
    ' <<< "$conf" | sort -u
}

# Function to get the public IP of the server
# This is crucial for Oracle Cloud where instances have private NICs but public IPs via gateway
get_public_ip() {
    curl -s https://ipinfo.io/ip || curl -s https://ifconfig.me
}

# Validate if a domain resolves to the server's public IP
validate_domain() {
    local domain_to_check="$1"
    # Get the server's public IP
    local public_ip; public_ip=$(get_public_ip)
    
    # If unable to get public IP, fallback to using local private IP (not recommended for Oracle Cloud, but as a last resort)
    if [[ -z "$public_ip" ]]; then
        echo -e "${YELLOW}Warning: Unable to obtain public IP, attempting to use local private IP for verification.${NC}" >&2
        public_ip=$(hostname -I | awk '{print $1}') # Get the first private IP
    fi

    if [[ -z "$public_ip" ]]; then
        echo -e "${RED}Error: Unable to obtain any valid IP for domain validation. Please check network connectivity or DNS settings.${NC}" >&2
        return 1
    fi

    local resolved_ips; resolved_ips=$(dig +short "$domain_to_check" A)

    if [[ -z "$resolved_ips" ]]; then
        echo "  -> ${YELLOW}Warning: Unable to resolve domain ${domain_to_check}. Please check domain configuration.${NC}" >&2
        return 1
    fi

    for resolved_ip in $resolved_ips; do
        if [[ "$resolved_ip" == "$public_ip" ]]; then
            echo "  -> ${GREEN}Validation successful: Domain ${domain_to_check} resolves to public IP ${resolved_ip} of this host.${NC}" >&2
            return 0
        fi
    done
    
    echo "  -> ${YELLOW}Validation failed: Domain ${domain_to_check} does not resolve to public IP ${public_ip} of this host.${NC}" >&2
    return 1
}

# --- Script Main Logic ---
check_dependencies

declare -a protocols=(); declare -a aliases=(); declare -a share_links=()
AUTHORITATIVE_ADDRESS=""

echo -e "\n${CYAN}Welcome to sing-box Automatic Smart Share Link Generator ✨${NC}"
echo "--------------------------------------------------"

mapfile -t config_files < <(find_singbox_configs)
if [ ${#config_files[@]} -eq 0 ]; then echo -e "${RED}No sing-box configuration files found. Exiting script.${NC}"; exit 1; fi
selected_config=""
if [ ${#config_files[@]} -eq 1 ]; then
    selected_config=${config_files[0]}
    echo "Automatically selected the only configuration file: $selected_config"
else
    echo -e "${YELLOW}Found the following sing-box configuration files:${NC}"; select config in "${config_files[@]}"; do if [[ -n "$config" ]]; then selected_config=$config; echo "You selected: $selected_config"; break; else echo "Invalid choice, please try again."; fi; done
fi

echo "--------------------------------------------------"
echo "Analyzing Nginx and sing-box configurations to find authoritative domain..."
declare -A proxy_map
while IFS=';' read -r internal_port server_name public_port tls_status; do
    if validate_domain "$server_name"; then
        proxy_map["$internal_port"]="$server_name;$public_port;$tls_status"
        if [[ -z "$AUTHORITATIVE_ADDRESS" ]]; then
            AUTHORITATIVE_ADDRESS=$server_name
            echo -e "${GREEN}Authoritative domain established via Nginx: ${AUTHORITATIVE_ADDRESS}${NC}"
        fi
    fi
done < <(find_nginx_proxies)

if [[ -z "$AUTHORITATIVE_ADDRESS" ]]; then
    while IFS= read -r inbound; do
        if [[ $(echo "$inbound" | jq -r '.type') == "vless" && $(echo "$inbound" | jq -r '.flow // ""') == *"vision"* ]]; then continue; fi
        server_name=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        if [[ -n "$server_name" ]]; then
            if validate_domain "$server_name"; then
                AUTHORITATIVE_ADDRESS=$server_name
                echo -e "${GREEN}Authoritative domain established via sing-box TLS: ${AUTHORITATIVE_ADDRESS}${NC}"
                break
            fi
        fi
    done < <(jq -c '.inbounds[]' "$selected_config")
fi

if [[ -z "$AUTHORITATIVE_ADDRESS" ]]; then
    echo -e "${YELLOW}Warning: Failed to automatically validate an authoritative domain from any configuration.${NC}"
    echo "Entering one-time manual configuration mode..."
    public_ip=$(get_public_ip)
    read -p "Detected public IP is [${public_ip}]. Please enter the domain shared by all configurations (recommended), or press Enter to use IP: " manual_addr < /dev/tty
    if [[ -z "$manual_addr" ]]; then AUTHORITATIVE_ADDRESS=$public_ip; else AUTHORITATIVE_ADDRESS=$manual_addr; fi
fi

echo "--------------------------------------------------"
echo "Generating links based on final determined egress information..."
while IFS= read -r inbound; do
    protocol_type=$(echo "$inbound" | jq -r '.type'); listen_port=$(echo "$inbound" | jq -r '.listen_port'); tag=$(echo "$inbound" | jq -r '.tag // "Default Alias"')
    final_address=""; final_port=""; final_host=""; final_tls_security="none"; source_of_truth=""

    is_reality=false
    if [[ "$protocol_type" == "vless" ]]; then
        if [[ $(echo "$inbound" | jq -r '.flow // ""') == *"vision"* ]]; then is_reality=true; fi
    fi

    if [[ -v proxy_map["$listen_port"] ]]; then
        source_of_truth="Nginx (Verified)"; proxy_info=${proxy_map["$listen_port"]}; IFS=';' read -r final_address final_port tls_status <<< "$proxy_info"
        if [[ "$tls_status" == "true" ]]; then final_tls_security="tls"; fi
    else
        final_address=$AUTHORITATIVE_ADDRESS
        final_port=$listen_port

        if [[ "$is_reality" == "true" ]]; then
            source_of_truth="Reality (Standalone)"
            final_tls_security="reality"
            final_host=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        else
            source_of_truth="Standalone"
            if [[ $(echo "$inbound" | jq -r '.tls.enabled // "false"') == "true" ]]; then
                final_tls_security="tls"
            else
                final_tls_security="none"
            fi
        fi
    fi

    if [[ -z "$final_host" ]]; then final_host=$final_address; fi

    echo -e "${GREEN}Egress for ${tag} (${listen_port}): ${final_address}:${final_port} (Source: ${source_of_truth})${NC}"
    if [[ -z "$final_address" ]] || [[ -z "$final_port" ]]; then echo -e "${RED}Address or port is empty, skipping this entry.${NC}"; continue; fi

    share_link=""; encoded_alias=$(jq -nr --arg str "$tag" '$str|@uri')
    case "$protocol_type" in
        vless|trojan|vmess|shadowsocks|hysteria2|tuic|naive|socks|http|wireguard)
            if [[ "$protocol_type" == "vless" ]]; then
                user_id=$(echo "$inbound" | jq -r '.users[0].uuid'); encoded_user_id=$(jq -nr --arg str "$user_id" '$str|@uri'); flow=$(echo "$inbound" | jq -r '.flow // ""'); transport_type=$(echo "$inbound" | jq -r '.transport.type // "tcp"');
                share_link="${protocol_type}://${encoded_user_id}@${final_address}:${final_port}"; params=""
                if [[ "$transport_type" == "ws" ]]; then
                    ws_path=$(echo "$inbound" | jq -r '.transport.path // ""'); encoded_path=$(jq -nr --arg str "$ws_path" '$str|@uri'); params="type=ws&security=${final_tls_security}&path=${encoded_path}&host=${final_host}"
                elif [[ "$is_reality" == "true" ]]; then
                    public_key=$(echo "$inbound" | jq -r '.tls.reality.public_key'); short_id=$(echo "$inbound" | jq -r '.tls.reality.short_id');
                    params="security=reality&sni=${final_host}&flow=${flow}&publicKey=${public_key}&shortId=${short_id}"
                else
                    params="security=${final_tls_security}&sni=${final_host}"
                fi
                share_link="${share_link}?${params}#${encoded_alias}"
            elif [[ "$protocol_type" == "trojan" ]]; then
                user_id=$(echo "$inbound" | jq -r '.users[0].password'); encoded_user_id=$(jq -nr --arg str "$user_id" '$str|@uri'); transport_type=$(echo "$inbound" | jq -r '.transport.type // "tcp"');
                if [[ "$transport_type" == "ws" ]]; then
                    ws_path=$(echo "$inbound" | jq -r '.transport.path // ""'); encoded_path=$(jq -nr --arg str "$ws_path" '$str|@uri'); share_link="trojan://${encoded_user_id}@${final_address}:${final_port}?type=ws&security=${final_tls_security}&path=${encoded_path}&host=${final_host}#${encoded_alias}"
                else
                    share_link="trojan://${encoded_user_id}@${final_address}:${final_port}?security=${final_tls_security}&sni=${final_host}#${encoded_alias}"
                fi
            elif [[ "$protocol_type" == "vmess" ]]; then
                uuid=$(echo "$inbound" | jq -r '.users[0].uuid'); transport_type=$(echo "$inbound" | jq -r '.transport.type // "tcp"'); vmess_json='{}'
                if [[ "$transport_type" == "ws" ]]; then
                    ws_path=$(echo "$inbound" | jq -r '.transport.path // ""'); vmess_json=$(jq -n --arg ps "$tag" --arg add "$final_address" --arg port "$final_port" --arg id "$uuid" --arg host "$final_host" --arg path "$ws_path" --arg tls "$final_tls_security" '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto", net:"ws", type:"none", host:$host, path:$path, tls:$tls}')
                else
                    vmess_json=$(jq -n --arg ps "$tag" --arg add "$final_address" --arg port "$final_port" --arg id "$uuid" --arg tls "$final_tls_security" '{v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto", net:"tcp", type:"none", tls:$tls}')
                fi; share_link="vmess://$(echo -n "$vmess_json" | base64 -w 0)"
            elif [[ "$protocol_type" == "shadowsocks" ]]; then
                method=$(echo "$inbound" | jq -r '.method'); password=$(echo "$inbound" | jq -r '.password'); user_info_b64=$(echo -n "${method}:${password}" | base64 -w 0); share_link="ss://${user_info_b64}@${final_address}:${final_port}#${encoded_alias}"
            elif [[ "$protocol_type" == "hysteria2" ]]; then
                auth=$(echo "$inbound" | jq -r '.users[0].password'); encoded_auth=$(jq -nr --arg str "$auth" '$str|@uri'); share_link="hysteria2://${encoded_auth}@${final_address}:${final_port}?sni=${final_host}#${encoded_alias}"
            elif [[ "$protocol_type" == "tuic" ]]; then
                uuid=$(echo "$inbound" | jq -r '.users[0].uuid'); password=$(echo "$inbound" | jq -r '.users[0].password'); share_link="tuic://${uuid}:${password}@${final_address}:${final_port}?sni=${final_host}#${encoded_alias}"
            elif [[ "$protocol_type" == "naive" ]]; then
                user=$(echo "$inbound" | jq -r '.users[0].username'); pass=$(echo "$inbound" | jq -r '.users[0].password'); share_link="naive+https://${user}:${pass}@${final_address}:${final_port}?padding=true#${encoded_alias}"
            elif [[ "$protocol_type" == "socks" || "$protocol_type" == "http" ]]; then
                user=$(echo "$inbound" | jq -r '.users[0].username // ""'); pass=$(echo "$inbound" | jq -r '.users[0].password // ""'); user_part=""; if [[ -n "$user" ]] && [[ -n "$pass" ]]; then user_part="${user}:${pass}@"; fi; share_link="${protocol_type}://${user_part}${final_address}:${final_port}#${encoded_alias}"
            elif [[ "$protocol_type" == "wireguard" ]]; then
                private_key=$(echo "$inbound" | jq -r '.private_key // ""'); peer_public_key=$(echo "$inbound" | jq -r '.peers[0].public_key // ""'); preshared_key=$(echo "$inbound" | jq -r '.peers[0].preshared_key // ""'); address1=$(echo "$inbound" | jq -r '.peers[0].allowed_ips[0] // ""'); address2=$(echo "$inbound" | jq -r '.peers[0].allowed_ips[1] // ""')
                if [[ -n "$private_key" ]] && [[ -n "$peer_public_key" ]]; then share_link="wg://${private_key}@${final_address}:${final_port}?public_key=${peer_public_key}&preshared_key=${preshared_key}&address=${address1}&address=${address2}#${encoded_alias}"; fi
            fi
            ;;
    esac

    if [[ -n "$share_link" ]]; then
        protocols+=("$protocol_type"); aliases+=("$tag"); share_links+=("$share_link")
    fi
done < <(jq -c '.inbounds[]' "$selected_config")

# --- Report generation phase ---
echo "--------------------------------------------------"
if [ ${#protocols[@]} -eq 0 ]; then echo -e "${RED}Processing complete, but no supported inbound proxies found.${NC}"; exit 0; fi
echo -e "${GREEN}✅ All configurations processed, summary report generated below:${NC}"
printf "\n"; printf "+----+-------------+--------------------------+----------------------------------------------------+\n"; printf "| %-2s | %-11s | %-24s | %-50s |\n" "ID" "Protocol" "Alias" "Share Link (Overview)"; printf "+----+-------------+--------------------------+----------------------------------------------------+\n"
for i in "${!protocols[@]}"; do
    display_link=${share_links[$i]}; if ((${#display_link} > 48)); then display_link="${display_link:0:45}..."; fi
    printf "| %-2s | %-11s | %-24s | %-50s |\n" "$((i+1))" "${protocols[$i]}" "${aliases[$i]}" "$display_link"
done
printf "+----+-------------+--------------------------+----------------------------------------------------+\n"; printf "\n"
echo -e "${CYAN}===================== Full Share Links (Copyable) =====================${NC}"
for i in "${!protocols[@]}"; do
    echo; echo -e "${YELLOW}===> ID: $((i+1)) | Alias: ${aliases[$i]}${NC}"; echo -e "${GREEN}${share_links[$i]}${NC}"
done
echo; echo -e "${CYAN}===================================================================${NC}"
echo -e "${CYAN}===================== QR Code Area (Scannable) =====================${NC}"
for i in "${!protocols[@]}"; do
    echo; echo -e "${YELLOW}===> ID: $((i+1)) | Protocol: ${protocols[$i]} | Alias: ${aliases[$i]}${NC}"; qrencode -t UTF8 -o - "${share_links[$i]}"
done
echo -e "${CYAN}===================================================================${NC}"
