[[ -n "${_NFTABLES_BACKEND_LOADED:-}" ]] && return 0
_NFTABLES_BACKEND_LOADED=1

backend_check() {
    command -v nft &>/dev/null || return 1
}

backend_setup() {
    local tcp_ports="${1:-}"
    local udp_ports="${2:-}"
    local interface="${3:-}"
    local table="${4:-$NFT_TABLE}"
    local chain="${5:-$NFT_CHAIN}"
    local queue_num="${6:-$NFT_QUEUE_NUM}"
    local mark="${7:-$NFT_MARK}"
    local comment="${8:-$NFT_RULE_COMMENT}"
    local chain_pre="${9:-$NFT_CHAIN_PRE}"

    local oif_clause=""
    local iif_clause=""
    if [[ -n "$interface" && "$interface" != "any" ]]; then
        if [[ "$interface" == *","* ]]; then
            local ifn ifnames=()
            IFS=',' read -ra _zapret_ifs <<< "$interface"
            for ifn in "${_zapret_ifs[@]}"; do
                ifn="${ifn// /}"
                [[ -n "$ifn" ]] && ifnames+=("\"$ifn\"")
            done
            if [[ ${#ifnames[@]} -gt 0 ]]; then
                local _iflist
                _iflist="$(IFS=,; echo "${ifnames[*]}")"
                oif_clause="oifname { $_iflist }"
                iif_clause="iifname { $_iflist }"
            fi
        else
            oif_clause="oifname \"$interface\""
            iif_clause="iifname \"$interface\""
        fi
    fi

    if elevate nft list tables 2>/dev/null | grep -q "$table"; then
        elevate nft flush chain "$table" "$chain" 2>/dev/null
        elevate nft delete chain "$table" "$chain" 2>/dev/null
        elevate nft flush chain "$table" "$chain_pre" 2>/dev/null
        elevate nft delete chain "$table" "$chain_pre" 2>/dev/null
        elevate nft delete table "$table" 2>/dev/null
    fi

    elevate nft add table "$table"
    elevate nft add chain "$table" "$chain" { type filter hook postrouting priority mangle\; }
    elevate nft add chain "$table" "$chain_pre" { type filter hook prerouting priority filter\; }

    # Virtual / VPN egress: one packet has one oif, Ethernet+Wi-Fi do not double-queue.
    # Skip so docker/TUN/loopback are not desync'd (v2ray TUN = singbox_tun).
    elevate nft add rule "$table" "$chain" \
        oifname '{ "lo", "docker0", "throne-tun", "singbox_tun" }' return \
        comment "\"Skip zapret for loopback, docker and VPN TUN\""
    elevate nft add rule "$table" "$chain" oifname "veth*" return \
        comment "\"Skip zapret for docker veth\""
    elevate nft add rule "$table" "$chain" oifname "br-*" return \
        comment "\"Skip zapret for docker bridges\""

    # Те же исключения для входящего направления: upstream завёл цепочку
    # prerouting, а правил пропуска в ней нет. Без зеркала ответные пакеты
    # от узлов VPN попадают в nfqueue и десинхронизируются.
    elevate nft add rule "$table" "$chain_pre" \
        iifname '{ "lo", "docker0", "throne-tun", "singbox_tun" }' return \
        comment "\"Skip zapret for loopback, docker and VPN TUN (in)\""
    elevate nft add rule "$table" "$chain_pre" iifname "veth*" return \
        comment "\"Skip zapret for docker veth (in)\""
    elevate nft add rule "$table" "$chain_pre" iifname "br-*" return \
        comment "\"Skip zapret for docker bridges (in)\""
    elevate nft add rule "$table" "$chain" meta mark "${THRONE_VPN_MARK:-0x2023}" return \
        comment "\"Skip zapret for Throne proxied traffic\""

    # v2rayN / direct VPS TLS: bypass nfqueue by destination (ipset-exclude inside nfqws is not enough under load)
    local exclude_file="${BASE_DIR:-}/${ZAPRET_VPS_EXCLUDE_FILE:-user-lists/ipset-exclude-user.txt}"
    if [[ -f "$exclude_file" ]]; then
        local vip vips=()
        while IFS= read -r vip || [[ -n "$vip" ]]; do
            vip="${vip%%#*}"
            vip="${vip// /}"
            [[ -z "$vip" ]] && continue
            vips+=("$vip")
        done < "$exclude_file"
        if [[ ${#vips[@]} -gt 0 ]]; then
            elevate nft add rule "$table" "$chain" ip daddr "{ $(IFS=,; echo "${vips[*]}") }" return \
                comment "\"Skip zapret for VPS VPN endpoints\""
            # Зеркало по источнику: ответы от тех же узлов не должны попадать
            # в очередь prerouting. Это защита канала, через который работает
            # управление системой.
            elevate nft add rule "$table" "$chain_pre" ip saddr "{ $(IFS=,; echo "${vips[*]}") }" return \
                comment "\"Skip zapret for VPS VPN endpoints (in)\""
        fi
    fi

    if [[ -n "$tcp_ports" ]]; then
        elevate nft add rule "$table" "$chain" $oif_clause \
            meta mark and "$mark" == 0 tcp dport "{$tcp_ports}" \
            ct original packets 1-6 queue num "$queue_num" bypass \
            comment "\"$comment\""
    fi

    if [[ -n "$udp_ports" ]]; then
        elevate nft add rule "$table" "$chain" $oif_clause \
            meta mark and "$mark" == 0 udp dport "{$udp_ports}" \
            ct original packets 1-6 queue num "$queue_num" bypass \
            comment "\"$comment\""
    fi

    if [[ -n "$tcp_ports" ]]; then
        elevate nft add rule "$table" "$chain_pre" $iif_clause \
            tcp sport "{$tcp_ports}" \
            ct reply packets 1-3 queue num "$queue_num" bypass \
            comment "\"$comment\""
    fi
}

backend_clear() {
    local table="${1:-$NFT_TABLE}"
    local chain="${2:-$NFT_CHAIN}"
    local chain_pre="${3:-$NFT_CHAIN_PRE}"

    if elevate nft list tables 2>/dev/null | grep -q "$table"; then
        if elevate nft list chain "$table" "$chain" >/dev/null 2>&1; then
            elevate nft flush chain "$table" "$chain" 2>/dev/null
            elevate nft delete chain "$table" "$chain" 2>/dev/null
        fi
        if elevate nft list chain "$table" "$chain_pre" >/dev/null 2>&1; then
            elevate nft flush chain "$table" "$chain_pre" 2>/dev/null
            elevate nft delete chain "$table" "$chain_pre" 2>/dev/null
        fi
        elevate nft delete table "$table" 2>/dev/null
    fi
}
