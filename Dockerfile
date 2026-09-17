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

RUN git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool && \
    pip3 install --break-system-packages -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt-tool && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark tcpdump wireshark-common \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN gem install one_gadget --no-document

RUN git clone --depth=1 https://github.com/DidierStevens/DidierStevensSuite /opt/DidierStevensSuite && \
    printf '%s\n' '#!/bin/sh' 'exec python3 /opt/DidierStevensSuite/pdf-parser.py "$@"' > /usr/local/bin/pdf-parser.py && \
    chmod +x /usr/local/bin/pdf-parser.py /opt/DidierStevensSuite/pdf-parser.py

RUN pip3 install --break-system-packages \
      six cryptography urllib3 requests gmpy2 pycryptodome tqdm z3-solver bitarray psutil factordb-pycli && \
    pip3 install --break-system-packages --no-deps git+https://github.com/RsaCtfTool/RsaCtfTool

# Scientific stack — numerical challenges (adversarial-ML, normalizing flows) need these.
# numpy/scipy are small; torch is multi-GB so it is intentionally NOT baked in — the agent
# can `pip install torch` on demand into its --system-site-packages venv when a challenge
# actually requires it (keeps the image small on constrained disks).
RUN pip3 install --break-system-packages numpy scipy || true

# RE / analysis libs the agent expected: capstone (already present via pwntools, pinned here
# for raw/sectionless disassembly), unicorn/keystone (emulation/assembly), wasmtime (wasm RNG
# challenges), websocket-client (WS-only backends), pillow + pytesseract (image work).
RUN pip3 install --break-system-packages \
      capstone unicorn keystone-engine wasmtime websocket-client pillow pytesseract || true

# Node + tesseract: JS-heavy web challenges / minified bundles, and OCR fallback.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nodejs tesseract-ocr \
      && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /ctf
WORKDIR /ctf
CMD ["/bin/bash"]
