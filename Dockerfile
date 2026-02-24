# CTF Agent — Kali Linux Docker Image
FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    gcc g++ build-essential cmake \
    curl wget git vim nano \
    file xxd hexedit \
    unzip p7zip-full tar unrar \
    netcat-traditional socat nmap \
    binutils gdb gdb-multiarch ltrace strace \
    radare2 patchelf upx-ucl \
    python3-pwntools \
    python3-pycryptodome \
    python3-requests \
    python3-gmpy2 \
    binwalk foremost exiftool \
    yara sleuthkit rizin \
    poppler-utils qpdf \
    steghide \
    pngcheck \
    hashcat john \
    openssl \
    gobuster nikto \
    sqlmap \
    ffuf \
    tshark wireshark-common \
    fcrackzip \
    sox ffmpeg \
    imagemagick \
    zbar-tools \
    multimon-ng \
    ruby ruby-dev \
    whois dnsutils \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends checksec \
    && (apt-get install -y --no-install-recommends pwndbg || true) \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Remove the broken apt unicorn stub so pip can install the real one
RUN apt-get update \
    && apt-get remove -y python3-unicorn 2>/dev/null || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Core packages — pure Python, should always succeed
RUN pip3 install --break-system-packages --ignore-installed \
    pwntools==4.12.0 \
    z3-solver==4.13.0.0 \
    sympy==1.13.3 \
    ecdsa==0.19.0 \
    ROPgadget==7.4 \
    tqdm==4.66.5 bitarray==2.9.2 factordb-pycli==1.3.0 \
    scapy==2.5.0 \
    randcrack==0.2.0 \
    pycryptodome==3.20.0 \
    Pillow==10.4.0 \
    requests==2.32.3

# Dev headers needed by C-extension packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgmp-dev libmpfr-dev libmpc-dev libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# C-extension / version-sensitive packages — isolated so one failure doesn't block others
RUN pip3 install --break-system-packages gmpy2==2.1.5 || true
RUN pip3 install --break-system-packages yara-python==4.5.1 || true
RUN pip3 install --break-system-packages stegoveritas==1.10 || true
RUN pip3 install --break-system-packages hashpumpy==1.2 || true
# frida-tools: try pinned first, fall back to latest (newer releases have Python 3.13 wheels)
RUN pip3 install --break-system-packages frida-tools==13.7.1 || \
    pip3 install --break-system-packages frida-tools || true

# jwt_tool — PyPI package broken on Python 3.13; install from source
RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && pip3 install --break-system-packages termcolor \
    && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

RUN pip3 install --break-system-packages volatility3==2.11.0 angr==9.2.129
RUN pip3 install --break-system-packages --ignore-installed 'capstone<6,>=5.0.1'

# Additional crypto/solver tools
RUN pip3 install --break-system-packages \
    uncompyle6 2>/dev/null || pip3 install --break-system-packages decompile3 2>/dev/null || true

# Didier Stevens PDF tooling
RUN git clone --depth=1 https://github.com/DidierStevens/DidierStevensSuite /opt/DidierStevensSuite \
    && ln -sf /opt/DidierStevensSuite/pdf-parser.py /usr/local/bin/pdf-parser.py \
    && chmod +x /usr/local/bin/pdf-parser.py

# RsaCtfTool — clone and create wrapper (don't use requirements.txt)
RUN git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool \
    && ls /opt/RsaCtfTool/ \
    && TOOL=$(find /opt/RsaCtfTool -maxdepth 1 -name "*.py" | grep -i rsa | head -1) \
    && echo "Found: $TOOL" \
    && printf '#!/bin/bash\npython3 '"$TOOL"' "$@"\n' > /usr/local/bin/RsaCtfTool \
    && chmod +x /usr/local/bin/RsaCtfTool

# Ruby gems: zsteg (PNG LSB steganography) + one_gadget (libc shell gadget finder)
RUN gem install zsteg one_gadget 2>/dev/null || true

# stegoveritas setup (image analysis for steganography)
RUN stegoveritas_setup 2>/dev/null || true

RUN apt-get update && apt-get install -y --no-install-recommends wordlists \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# Install pwndbg from source (not in current Kali apt snapshot)
RUN git clone --depth=1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && (cd /opt/pwndbg && DEBIAN_FRONTEND=noninteractive ./setup.sh 2>&1 | tail -10) \
    && echo "pwndbg installed from source" \
    || echo "pwndbg source install failed — GDB still available without it"

RUN mkdir -p /ctf
WORKDIR /ctf
CMD ["/bin/bash"]
