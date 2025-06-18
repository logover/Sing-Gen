#!/bin/bash

# =========================================================================
# sing-box 全自动智能分享链接生成器
# 兼容支持: CentOS/RHEL/Fedora 和 Arch Linux 
# =========================================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 函数定义 ---

# 检查并自动安装依赖（跨平台版）
check_dependencies() {
    local missing_deps=()
    echo "正在检查必要的依赖程序..."

    # 检查通用依赖
    for dep in jq qrencode nginx perl; do
        if ! command -v "$dep" &> /dev/null; then missing_deps+=("$dep"); fi
    done
    # 检查 dig 命令
    if ! command -v "dig" &> /dev/null; then
        # dig 命令在不同发行版中由不同包提供
        missing_deps+=("dig_placeholder")
    fi
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        echo -e "${GREEN}所有依赖均已安装。${NC}"
        return
    fi
    
    # 检测操作系统发行版
    local os_id=""
    if [ -f /etc/os-release ]; then
        os_id=$(grep -oP '^ID=\K\w+' /etc/os-release)
    else
        echo -e "${RED}错误: 无法识别您的操作系统发行版。请手动安装依赖。${NC}"
        exit 1
    fi
    
    local pkg_manager_install=""
    local pkg_manager_update=""
    local dns_pkg_name=""

    # 根据发行版设置包管理器和包名
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
            echo -e "${RED}错误: 不支持的操作系统发行版: '$os_id'。请手动安装以下依赖: ${missing_deps[*]}${NC}"
            exit 1
            ;;
    esac

    # 替换占位符为正确的包名
    missing_deps=("${missing_deps[@]/dig_placeholder/$dns_pkg_name}")

    echo -e "${YELLOW}警告: 检测到以下依赖程序未安装: ${missing_deps[*]}${NC}"
    read -p "是否要自动为您安装? (Y/n) " -n 1 -r REPLY < /dev/tty; echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        echo "正在开始安装..."
        # 如果有更新命令，则执行
        if [[ -n "$pkg_manager_update" ]]; then
            $pkg_manager_update || { echo -e "${RED}错误: 包列表更新失败。${NC}"; exit 1; }
        fi
        
        # 安装缺失的包
        $pkg_manager_install "${missing_deps[@]}" || { echo -e "${RED}错误: 依赖安装失败。${NC}"; exit 1; }
        
        echo -e "${GREEN}依赖安装成功！脚本将继续运行。${NC}"
    else
        echo -e "${RED}用户取消安装。已退出。${NC}"; exit 1
    fi
}


find_service_file() {
    local service_name="$1"; local path; path=$(systemctl show -p FragmentPath "${service_name}" 2>/dev/null | cut -d'=' -f2); if [[ -n "$path" && -f "$path" ]]; then echo "$path"; else find /etc/systemd/ /usr/lib/systemd/ -name "${service_name}.service" -print -quit; fi
}
find_singbox_configs() {
    local service_file; service_file=$(find_service_file "sing-box"); if [[ -z "$service_file" ]]; then echo -e "${RED}错误: 找不到 sing-box.service 文件。${NC}" >&2; return 1; fi; local config_path; config_path=$(grep -oP '(-C|--config)\s+\K(\S+)' "$service_file" | head -n 1); if [[ -z "$config_path" ]]; then config_path="/etc/sing-box/"; fi; if [[ -d "$config_path" ]]; then find "$config_path" -maxdepth 1 -type f -name "*.json"; elif [[ -f "$config_path" ]]; then echo "$config_path"; else echo -e "${RED}错误: 在 ${service_file} 中找不到有效的配置路径。${NC}" >&2; return 1; fi
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
get_public_ip() {
    curl -s https://ipinfo.io/ip || curl -s https://ifconfig.me || hostname -I | awk '{print $1}'
}
validate_domain() {
    local domain_to_check="$1"; local local_ips; local_ips=$(hostname -I); local resolved_ips; resolved_ips=$(dig +short "$domain_to_check" A);
    if [[ -z "$resolved_ips" ]]; then echo "  -> ${YELLOW}警告: 无法解析域名 ${domain_to_check}。${NC}" >&2; return 1; fi
    for resolved_ip in $resolved_ips; do
        for local_ip in $local_ips; do
            if [[ "$resolved_ip" == "$local_ip" ]]; then echo "  -> ${GREEN}验证成功: 域名 ${domain_to_check} 解析到本机IP ${resolved_ip}。${NC}" >&2; return 0; fi
        done
    done
    echo "  -> ${YELLOW}验证失败: 域名 ${domain_to_check} 未解析到本机。${NC}" >&2; return 1
}

# --- 脚本主逻辑 ---
check_dependencies

declare -a protocols=(); declare -a aliases=(); declare -a share_links=()
AUTHORITATIVE_ADDRESS=""

echo -e "\n${CYAN}欢迎使用 sing-box 全自动智能分享链接生成器 ✨${NC}"
echo "--------------------------------------------------"

mapfile -t config_files < <(find_singbox_configs)
if [ ${#config_files[@]} -eq 0 ]; then echo -e "${RED}未能找到任何 sing-box 配置文件。脚本退出。${NC}"; exit 1; fi
selected_config=""
if [ ${#config_files[@]} -eq 1 ]; then
    selected_config=${config_files[0]}
    echo "自动选择唯一的配置文件: $selected_config"
else
    echo -e "${YELLOW}找到以下 sing-box 配置文件:${NC}"; select config in "${config_files[@]}"; do if [[ -n "$config" ]]; then selected_config=$config; echo "您选择了: $selected_config"; break; else echo "无效的选择，请重试。"; fi; done
fi

echo "--------------------------------------------------"
echo "正在分析 Nginx 和 sing-box 配置以寻找权威域名..."
declare -A proxy_map
while IFS=';' read -r internal_port server_name public_port tls_status; do
    if validate_domain "$server_name"; then
        proxy_map["$internal_port"]="$server_name;$public_port;$tls_status"
        if [[ -z "$AUTHORITATIVE_ADDRESS" ]]; then
            AUTHORITATIVE_ADDRESS=$server_name
            echo -e "${GREEN}通过Nginx确立权威域名: ${AUTHORITATIVE_ADDRESS}${NC}"
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
                echo -e "${GREEN}通过sing-box TLS确立权威域名: ${AUTHORITATIVE_ADDRESS}${NC}"
                break
            fi
        fi
    done < <(jq -c '.inbounds[]' "$selected_config")
fi

if [[ -z "$AUTHORITATIVE_ADDRESS" ]]; then
    echo -e "${YELLOW}警告：未能从任何配置中自动验证一个权威域名。${NC}"
    echo "将进入一次性手动配置模式..."
    public_ip=$(get_public_ip)
    read -p "检测到公网IP是 [${public_ip}]。请输入所有配置共用的域名 (推荐), 或直接回车使用IP: " manual_addr < /dev/tty
    if [[ -z "$manual_addr" ]]; then AUTHORITATIVE_ADDRESS=$public_ip; else AUTHORITATIVE_ADDRESS=$manual_addr; fi
fi

echo "--------------------------------------------------"
echo "正在根据最终确定的出口信息生成链接..."
while IFS= read -r inbound; do
    protocol_type=$(echo "$inbound" | jq -r '.type'); listen_port=$(echo "$inbound" | jq -r '.listen_port'); tag=$(echo "$inbound" | jq -r '.tag // "默认别名"')
    final_address=""; final_port=""; final_host=""; final_tls_security="none"; source_of_truth=""
    
    is_reality=false
    if [[ "$protocol_type" == "vless" ]]; then
        if [[ $(echo "$inbound" | jq -r '.flow // ""') == *"vision"* ]]; then is_reality=true; fi
    fi

    if [[ -v proxy_map["$listen_port"] ]]; then
        source_of_truth="Nginx (已验证)"; proxy_info=${proxy_map["$listen_port"]}; IFS=';' read -r final_address final_port tls_status <<< "$proxy_info"
        if [[ "$tls_status" == "true" ]]; then final_tls_security="tls"; fi
    else
        final_address=$AUTHORITATIVE_ADDRESS
        final_port=$listen_port
        
        if [[ "$is_reality" == "true" ]]; then
            source_of_truth="Reality (独立运行)"
            final_tls_security="reality"
            final_host=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        else
            source_of_truth="独立运行"
            if [[ $(echo "$inbound" | jq -r '.tls.enabled // "false"') == "true" ]]; then
                 final_tls_security="tls"
            else
                 final_tls_security="none"
            fi
        fi
    fi
    
    if [[ -z "$final_host" ]]; then final_host=$final_address; fi
    
    echo -e "${GREEN}为 ${tag} (${listen_port}) 确定出口: ${final_address}:${final_port} (来源: ${source_of_truth})${NC}"
    if [[ -z "$final_address" ]] || [[ -z "$final_port" ]]; then echo -e "${RED}地址或端口为空, 跳过此条目。${NC}"; continue; fi

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

# --- 报告生成阶段 ---
echo "--------------------------------------------------"
if [ ${#protocols[@]} -eq 0 ]; then echo -e "${RED}处理完成，但未找到任何支持的入站代理。${NC}"; exit 0; fi
echo -e "${GREEN}✅ 所有配置处理完毕，生成汇总报告如下：${NC}"
printf "\n"; printf "+----+-------------+--------------------------+----------------------------------------------------+\n"; printf "| %-2s | %-11s | %-24s | %-50s |\n" "ID" "协议" "别名 (Alias)" "分享链接 (概览)"; printf "+----+-------------+--------------------------+----------------------------------------------------+\n"
for i in "${!protocols[@]}"; do
    display_link=${share_links[$i]}; if ((${#display_link} > 48)); then display_link="${display_link:0:45}..."; fi
    printf "| %-2s | %-11s | %-24s | %-50s |\n" "$((i+1))" "${protocols[$i]}" "${aliases[$i]}" "$display_link"
done
printf "+----+-------------+--------------------------+----------------------------------------------------+\n"; printf "\n"
echo -e "${CYAN}===================== 完整分享链接 (可直接复制) =====================${NC}"
for i in "${!protocols[@]}"; do
    echo; echo -e "${YELLOW}===> ID: $((i+1)) | 别名: ${aliases[$i]}${NC}"; echo -e "${GREEN}${share_links[$i]}${NC}"
done
echo; echo -e "${CYAN}===================================================================${NC}"
echo -e "${CYAN}===================== 二维码区域 (可直接扫描) =====================${NC}"
for i in "${!protocols[@]}"; do
    echo; echo -e "${YELLOW}===> ID: $((i+1)) | 协议: ${protocols[$i]} | 别名: ${aliases[$i]}${NC}"; qrencode -t UTF8 -o - "${share_links[$i]}"
done
echo -e "${CYAN}===================================================================${NC}"
