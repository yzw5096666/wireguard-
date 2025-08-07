#!/bin/bash
# WireGuard 多端口多用户管理脚本（服务端Peer段增删同步所有用户，彻底修正SaveConfig覆盖问题）

WG_DIR="/etc/wireguard"
SYSCTL_FILE="/etc/sysctl.conf"
DNS_FILE="$WG_DIR/.global_dns"
DEFAULT_DNS="8.8.8.8"

set -e

install_deps() {
  if ! command -v iptables &>/dev/null; then
    if command -v apt &>/dev/null; then
      apt update && apt install -y iptables
    elif command -v yum &>/dev/null; then
      yum install -y iptables
    else
      echo "不支持的系统，无法自动安装iptables"
      exit 1
    fi
  fi
  if ! command -v wg &>/dev/null; then
    if command -v apt &>/dev/null; then
      apt update && apt install -y wireguard-tools
    elif command -v yum &>/dev/null; then
      yum install -y epel-release
      yum install -y wireguard-tools
    else
      echo "不支持的系统，无法自动安装wireguard"
      exit 1
    fi
  fi
}

enable_ip_forward() {
  if ! grep -q "net.ipv4.ip_forward=1" $SYSCTL_FILE 2>/dev/null; then
    echo 'net.ipv4.ip_forward=1' >> $SYSCTL_FILE
  fi
  sysctl -w net.ipv4.ip_forward=1
}

get_pub_nic() {
  ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1
}

add_nat_rule() {
  local SUBNET="$1"
  local PUB_NIC
  PUB_NIC="$(get_pub_nic)"
  if [[ -z $PUB_NIC ]]; then
    echo "无法自动检测公网网卡名，请手动设置NAT。" >&2
    return 1
  fi
  if ! iptables -t nat -C POSTROUTING -s $SUBNET -o $PUB_NIC -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s $SUBNET -o $PUB_NIC -j MASQUERADE
    echo "已为 $SUBNET 添加 NAT 出口规则（$PUB_NIC）"
    netfilter-persistent save
  fi
}

list_instances() {
  ls ${WG_DIR}/wg*.conf 2>/dev/null | awk -F/ '{print $NF}' | sed 's/\.conf$//' | sort
}

instance_exists() {
  [[ -f "${WG_DIR}/$1.conf" ]]
}

used_subnets() {
  grep -h '^Address' ${WG_DIR}/wg*.conf 2>/dev/null | awk '{print $3}' | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)\..*$/\1/' | sort | uniq
}

generate_unique_subnet() {
  local used subnet subnet_base
  used=$(used_subnets)
  for try in $(seq 1 1000); do
    r1=$((RANDOM%200+10))
    r2=$((RANDOM%200+10))
    subnet="10.${r1}.${r2}.1/24"
    subnet_base="10.${r1}.${r2}"
    if ! echo "$used" | grep -qw "$subnet_base"; then
      echo "$subnet"
      return
    fi
  done
  echo "无法自动分配唯一虚拟网段，请手动分配" >&2
  exit 1
}

next_free_port() {
  local used_ports
  used_ports=$(grep -h 'ListenPort' ${WG_DIR}/*.conf 2>/dev/null | awk '{print $3}' | sort -n)
  local port=51820
  while echo "$used_ports" | grep -q "^$port$"; do port=$((port+1)); done
  echo "$port"
}

get_dns() {
  if [[ -f $DNS_FILE ]]; then
    cat "$DNS_FILE"
  else
    echo "$DEFAULT_DNS"
  fi
}

set_dns() {
  local value
  echo
  echo "请选择DNS类型："
  echo "1) 8.8.8.8"
  echo "2) 自定义"
  read -rp "请输入选择[1-2]: " choice
  case "$choice" in
    1)
      value="8.8.8.8"
      ;;
    2)
      read -rp "请输入自定义DNS（如114.114.114.114,223.5.5.5）: " custom_dns
      value="$custom_dns"
      ;;
    *)
      echo "无效选择，保留原设置"
      return
      ;;
  esac
  echo "$value" > "$DNS_FILE"
  echo "DNS设置已更新！"
}

show_dns() {
  local dns_set
  dns_set=$(get_dns)
  echo "当前DNS：$dns_set"
}

is_running() {
  ip link show "$1" &>/dev/null
}

# 重新生成服务端配置（保留Interface段，Peer段根据现用户全部重建）
rebuild_server_conf() {
  local INSTANCE="$1"
  local CONF="$WG_DIR/${INSTANCE}.conf"
  local USERS_DIR="$WG_DIR/${INSTANCE}-users"
  local PRIVKEY PUBKEY ADDR PORT
  PRIVKEY=$(cat "$WG_DIR/${INSTANCE}_private")
  PUBKEY=$(cat "$WG_DIR/${INSTANCE}_public")
  ADDR=$(grep Address "$CONF" | awk '{print $3}')
  PORT=$(grep ListenPort "$CONF" | awk '{print $3}')
  # Interface段
  cat > "$CONF" <<EOF
[Interface]
Address = $ADDR
SaveConfig = true
ListenPort = $PORT
PrivateKey = $PRIVKEY
EOF
  # Peer段
  local user_file client_pub client_ip
  for user_file in "$USERS_DIR"/*_client.conf; do
    [ -f "$user_file" ] || continue
    client_pub=$(grep PrivateKey "$user_file" | awk '{print $3}' | wg pubkey)
    client_ip=$(grep '^Address' "$user_file" | awk '{print $3}')
    cat >> "$CONF" <<EOF

[Peer]
PublicKey = $client_pub
AllowedIPs = $client_ip
EOF
  done
}

create_instance() {
  echo
  read -rp "请输入新端口实例名称 (如 wg100，需以wg开头): " INSTANCE
  [[ -z "$INSTANCE" ]] && { echo "实例名不能为空"; return; }
  if instance_exists "$INSTANCE"; then
    echo "实例 $INSTANCE 已存在!"
    return
  fi

  PORT=$(next_free_port)
  read -rp "请输入监听端口 [$PORT]: " INPUT_PORT
  [[ -n "$INPUT_PORT" ]] && PORT="$INPUT_PORT"

  SUBNET=$(generate_unique_subnet)
  echo "为你自动分配虚拟网段: $SUBNET"

  UMASK_ORIG=$(umask)
  umask 077
  mkdir -p "$WG_DIR/${INSTANCE}-users"
  PRIVKEY=$(wg genkey)
  PUBKEY=$(echo "$PRIVKEY" | wg pubkey)
  echo "$PRIVKEY" > "$WG_DIR/${INSTANCE}_private"
  echo "$PUBKEY" > "$WG_DIR/${INSTANCE}_public"

  cat > "${WG_DIR}/${INSTANCE}.conf" <<EOF
[Interface]
Address = $SUBNET
ListenPort = $PORT
PrivateKey = $PRIVKEY
SaveConfig = true
EOF

  SUBNET_CIDR=$(echo $SUBNET | sed -E 's/([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+\/([0-9]+)/\1.0\/\2/')
  add_nat_rule "$SUBNET_CIDR"

  umask "$UMASK_ORIG"
  echo "已创建实例 $INSTANCE，监听端口 $PORT，虚拟网段 $SUBNET"
}

delete_instance() {
  echo
  list_instances
  read -rp "输入要删除端口的实例名: " INSTANCE
  if ! instance_exists "$INSTANCE"; then
    echo "实例 $INSTANCE 不存在"
    return
  fi
  if is_running "$INSTANCE"; then
    wg-quick down $INSTANCE 2>/dev/null || true
  fi
  rm -f "$WG_DIR/${INSTANCE}.conf" "$WG_DIR/${INSTANCE}_private" "$WG_DIR/${INSTANCE}_public"
  rm -rf "$WG_DIR/${INSTANCE}-users"
  echo "已删除实例 $INSTANCE"
}

uninstall_all() {
  echo
  echo "确定要卸载所有WireGuard实例和相关配置吗？[y/N]"
  read -r CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || return

  for i in $(list_instances); do
    if is_running "$i"; then
      wg-quick down "$i" 2>/dev/null || true
    fi
    rm -f "$WG_DIR/${i}.conf" "$WG_DIR/${i}_private" "$WG_DIR/${i}_public"
    rm -rf "$WG_DIR/${i}-users"
  done
  rm -f "$DNS_FILE"
  if command -v apt &>/dev/null; then
    apt-get remove --purge -y wireguard-tools wireguard 2>/dev/null
  elif command -v yum &>/dev/null; then
    yum remove -y wireguard-tools 2>/dev/null
  fi
  echo "已卸载所有WireGuard和实例"
}

manage_instance() {
  INSTANCE="$1"
  CONF="$WG_DIR/${INSTANCE}.conf"
  USERS_DIR="$WG_DIR/${INSTANCE}-users"
  SERVER_PUBKEY=$(cat "$WG_DIR/${INSTANCE}_public")
  ADDRESS_BASE=$(grep Address "$CONF" | awk '{print $3}' | cut -d. -f1-3)
  SUBNET_MASK=$(grep Address "$CONF" | awk '{print $3}' | cut -d/ -f2)
  if [[ -z "$SUBNET_MASK" ]]; then SUBNET_MASK=24; fi

  while true; do
    echo
    echo "---- 管理端口 $INSTANCE ----"
    echo "1) 增加用户"
    echo "2) 删除用户"
    echo "3) 列出用户"
    echo "4) 启动端口"
    echo "5) 停止端口"
    echo "6) 查看配置"
    echo "0) 返回主菜单"
    echo
    read -rp "请选择操作: " ACTION
    case "$ACTION" in
      1)
        read -rp "输入用户名: " USER
        if [[ -f "$USERS_DIR/${USER}_client.conf" ]]; then
          echo "该用户已存在"
          continue
        fi
        CLIENT_PRIV=$(wg genkey)
        CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
        # 分配可用IP
        ID=2
        while [[ -f "$USERS_DIR/.${ID}_used" ]]; do ID=$((ID+1)); done
        touch "$USERS_DIR/.${ID}_used"
        CLIENT_IP="${ADDRESS_BASE}.${ID}/32"
        DNS_VALUE=$(get_dns)
        ENDPOINT="$(curl -s ifconfig.me):$(grep ListenPort "$CONF" | awk '{print $3}')"
        cat > "$USERS_DIR/${USER}_client.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_IP
DNS = $DNS_VALUE

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
        # 重新生成服务端配置（同步所有用户）
        if is_running "$INSTANCE"; then
          wg-quick down $INSTANCE 2>/dev/null || true
        fi
        rebuild_server_conf "$INSTANCE"
        wg-quick up $INSTANCE
        echo "用户 $USER 添加完成，配置文件: $USERS_DIR/${USER}_client.conf"
        ;;
      2)
        read -rp "输入要删除的用户名: " USER
        if [[ ! -f "$USERS_DIR/${USER}_client.conf" ]]; then
          echo "用户不存在"
          continue
        fi
        rm -f "$USERS_DIR/${USER}_client.conf"
        # 释放IP占用
        for ipfile in "$USERS_DIR"/.*_used; do
          [[ -f $ipfile ]] || continue
          IPNUM="${ipfile##*.}"
          [[ "$USER" == "$(basename "$ipfile" | cut -d_ -f1)" ]] && rm -f "$ipfile"
        done
        if is_running "$INSTANCE"; then
          wg-quick down $INSTANCE 2>/dev/null || true
        fi
        rebuild_server_conf "$INSTANCE"
        wg-quick up $INSTANCE
        echo "已删除用户 $USER"
        ;;
      3)
        user_files=("$USERS_DIR"/*_client.conf)
        if [ ! -e "${user_files[0]}" ]; then
            echo "当前用户: 无"
        else
            echo "当前用户:"
            for f in "${user_files[@]}"; do
                basename "$f" | sed 's/_client.conf//'
            done
        fi
        ;;
      4)
        if is_running "$INSTANCE"; then
          echo "端口 $INSTANCE 已启动，无需重复操作"
        else
          wg-quick up $INSTANCE && echo "端口 $INSTANCE 启动成功"
        fi
        ;;
      5)
        if ! is_running "$INSTANCE"; then
          echo "端口 $INSTANCE 已处于停止状态"
        else
          wg-quick down $INSTANCE && echo "端口 $INSTANCE 已停止"
        fi
        ;;
      6)
        cat "$CONF"
        ;;
      0)
        break
        ;;
      *)
        echo "无效输入"
        ;;
    esac
  done
}

print_main_menu() {
  echo
  echo "========= WireGuard 多端口管理 ========="
  echo "1) 创建新端口"
  echo "2) 查看已有端口"
  echo "3) 删除端口"
  echo "4) 卸载所有WireGuard实例"
  echo "5) 全局DNS设置"
  echo "6) 显示当前DNS设置"
  echo "0) 退出"
  echo "======================================"
  echo
}

install_deps
enable_ip_forward

while true; do
  print_main_menu
  read -rp "请选择操作: " CHOICE
  case "$CHOICE" in
    1)
      create_instance
      ;;
    2)
      echo
      INSTANCES=$(list_instances)
      if [[ -z "$INSTANCES" ]]; then
        echo "没有可用端口实例"
        continue
      fi
      echo "$INSTANCES"
      read -rp "输入要管理的实例名: " INSTANCE
      if instance_exists "$INSTANCE"; then
        manage_instance "$INSTANCE"
      else
        echo "实例 $INSTANCE 不存在"
      fi
      ;;
    3)
      delete_instance
      ;;
    4)
      uninstall_all
      exit 0
      ;;
    5)
      set_dns
      ;;
    6)
      show_dns
      ;;
    0)
      exit 0
      ;;
    *)
      echo "无效输入"
      ;;
  esac
done