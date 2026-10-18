"""Zip dist\\PacketStory into PacketStory-Portable.zip (used by build_exe.bat)."""
import os
import zipfile

SRC, OUT = os.path.join("dist", "PacketStory"), "PacketStory-Portable.zip"

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, _, names in os.walk(SRC):
        for n in names:
            p = os.path.join(root, n)
            z.write(p, os.path.join("PacketStory", os.path.relpath(p, SRC)))
print(f"{OUT}: {os.path.getsize(OUT) / 1048576:.1f} MB")
