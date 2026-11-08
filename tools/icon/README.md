# App icon

`icon.svg` is the artwork (a blue rounded square, a white lock and a fingerprint badge). To rebuild the `.icns`:

1. Render the SVG to a 1024 px PNG (for example with macOS Quick Look: `qlmanage -t -s 1024 -o . icon.svg`).
2. `python3 mask.py icon.svg.png icon-1024.png` makes everything outside the rounded square transparent.
3. Build an `.iconset` with `sips -z` for 16, 32, 128, 256 and 512 px (plus @2x) and run `iconutil -c icns`.
4. Copy the result to `src/secreds/assets/seCreds.icns`.
