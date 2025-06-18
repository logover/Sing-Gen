# Sing-Gen ✨

**一个智能、全自动的 `sing-box` 分享链接生成器。**

这个脚本能够自动分析您服务器上的 `sing-box` 和 `Nginx` 配置，智能地生成可供主流客户端直接导入的分享链接和二维码。

---

## 兼容性 (Compatibility)

目前已在 **Ubuntu 24.04** 上测试通过，并加入了对 **CentOS/RHEL/Fedora** 和 **Arch Linux** 的兼容支持。理论上兼容所有使用 `systemd` 的现代Linux发行版。

## 使用方法 (Usage)

1.  **下载脚本**
    ```bash
    # 使用 curl 或 wget 下载脚本
    curl -o https://raw.githubusercontent.com/logover/Sing-Gen/refs/heads/main/SingGen.sh
    ```

2.  **授予执行权限**
    ```bash
    chmod +x sing-gen.sh
    ```

3.  **运行脚本**
    ```bash
    ./sing-gen.sh
    ```

## 依赖 (Dependencies)
本脚本依赖以下工具。在首次运行时，脚本会自动检测并提示您安装缺失的组件。

* `jq`
* `qrencode`
* `nginx`
* `perl`
* `dnsutils` (Debian/Ubuntu) / `bind-utils` (CentOS/RHEL) / `bind` (Arch)
