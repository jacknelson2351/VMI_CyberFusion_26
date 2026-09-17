import subprocess

# Run the ELF binary and capture output
result = subprocess.run(["./11_extracted/rev_11/1"], capture_output=True)
output = result.stdout.decode().strip()

print(f"Output: {output}")
