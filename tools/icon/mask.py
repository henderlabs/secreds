"""Make everything outside the icon's rounded square transparent (with smooth edges). Pure standard library."""
import zlib, struct, math, sys
src, dst = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read(); i = 8; idat = b''
while i < len(d):
    n, t = struct.unpack('>I4s', d[i:i+8]); c = d[i+8:i+8+n]
    if t == b'IHDR': w, h, bd, ct = struct.unpack('>IIBB', c[:10])
    if t == b'IDAT': idat += c
    i += 12 + n
assert bd == 8 and ct == 6, "expects 8-bit RGBA"
raw = zlib.decompress(idat); bpp = 4; stride = w * bpp
rows = []; prev = bytearray(stride)
for y in range(h):
    f = raw[y*(stride+1)]; line = bytearray(raw[y*(stride+1)+1:(y+1)*(stride+1)])
    if f == 1:
        for x in range(bpp, stride): line[x] = (line[x] + line[x-bpp]) & 255
    elif f == 2:
        for x in range(stride): line[x] = (line[x] + prev[x]) & 255
    elif f == 3:
        for x in range(stride): line[x] = (line[x] + (((line[x-bpp] if x >= bpp else 0) + prev[x]) >> 1)) & 255
    elif f == 4:
        for x in range(stride):
            a = line[x-bpp] if x >= bpp else 0; b = prev[x]; cc = prev[x-bpp] if x >= bpp else 0
            p = a + b - cc; pa, pb, pc = abs(p-a), abs(p-b), abs(p-cc)
            pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else cc)
            line[x] = (line[x] + pr) & 255
    rows.append(line); prev = line
X0, Y0, S, R = 100, 100, 824, 185          # rounded square used by the artwork
cx, cy = X0 + S/2, Y0 + S/2; half = S/2 - R
out = bytearray()
for y in range(h):
    line = rows[y]
    for x in range(w):
        qx = abs(x + 0.5 - cx) - half; qy = abs(y + 0.5 - cy) - half
        dist = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - R   # signed distance, <0 inside
        a = max(0.0, min(1.0, 0.5 - dist))
        o = x*4; line[o+3] = int(line[o+3] * a + 0.5) if a < 1 else line[o+3]
        if a == 0: line[o] = line[o+1] = line[o+2] = 0
    out += b'\x00' + line
def chunk(t, body): return struct.pack('>I', len(body)) + t + body + struct.pack('>I', zlib.crc32(t + body) & 0xffffffff)
png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(bytes(out), 6)) + chunk(b'IEND', b'')
open(dst, 'wb').write(png); print("wrote", dst, len(png), "bytes")
