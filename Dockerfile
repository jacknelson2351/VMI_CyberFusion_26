# CTF Agent - practical full-spectrum CTF image (without niche/slow extras)
FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    gcc g++ build-essential cmake make \
    curl wget git vim nano \
    file xxd hexedit fdisk bsdextrautils \
    unzip p7zip-full tar unrar \
    netcat-traditional socat nmap \
    binutils gdb gdb-multiarch ltrace strace patchelf checksec \
    rizin upx-ucl \
    binwalk foremost exiftool yara sleuthkit \
    poppler-utils qpdf \
    steghide pngcheck zbar-tools multimon-ng \
    sox openssl \
    gobuster nikto sqlmap ffuf \
    ripgrep jq yq ripmime rlwrap pv tcpflow whatweb wfuzz onesixtyone enum4linux-ng hashid cewl \
    fcrackzip \
    whois dnsutils \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Keep the most-used Python CTF tooling; install robustly across Python minor versions.
RUN pip3 install --break-system-packages --upgrade pip setuptools wheel && \
    set -eux; \
    for pkg in \
      "pwntools==4.12.0" \
      "z3-solver==4.13.0.0" \
      "sympy==1.13.3" \
      "pycryptodome==3.20.0" \
      "requests==2.32.3" \
      "scapy==2.5.0" \
      "ROPgadget==7.4" \
      "tqdm==4.66.5" \
      "bitarray==2.9.2" \
      "ecdsa==0.19.0" \
      "randcrack==0.2.0"; do \
        if ! pip3 install --break-system-packages --ignore-installed "$pkg"; then \
          base="${pkg%%==*}"; \
          echo "Pinned install failed for $pkg, retrying unpinned $base"; \
          pip3 install --break-system-packages --ignore-installed "$base" || true; \
        fi; \
    done

RUN pip3 install --break-system-packages beautifulsoup4 requests-toolbelt pyjwt python-magic || true

RUN pip3 install --break-system-packages uncompyle6 || pip3 install --break-system-packages decompile3 || true

RUN mkdir -p /ctf
WORKDIR /ctf
CMD ["/bin/bash"]
