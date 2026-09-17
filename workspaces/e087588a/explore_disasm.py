# Fixed handling of empty lines in disassembly output

import subprocess

start_addr = 0x4011c5
end_addr = start_addr + 0x50

dump_cmd = ["objdump", "-d", "/ctf/roulette"]

result = subprocess.run(dump_cmd, capture_output=True, text=True)
disasm = result.stdout

lines = disasm.splitlines()

inside = False
extracted_lines = []
for line in lines:
    if f"{start_addr:x}" in line.lower():
        inside = True
    if inside:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address_str = parts[0]
        try:
            addr = int(address_str, 16)
            if addr > end_addr:
                break
            extracted_lines.append(line)
        except:
            continue

# Print the extracted lines
for l in extracted_lines:
    print(l)