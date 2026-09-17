from PIL import Image
import sys

input_path = r"d:\智盾\bee\frontend\public\download.webp"
output_path = r"d:\智盾\bee\frontend\public\bee-logo.png"

img = Image.open(input_path).convert("RGBA")
width, height = img.size

crop_bottom = int(height * 0.08)
img = img.crop((0, 0, width, height - crop_bottom))

pixels = img.load()
w, h = img.size

for y in range(h):
    for x in range(w):
        r, g, b, a = pixels[x, y]
        brightness = (r + g + b) / 3.0
        if brightness < 15:
            pixels[x, y] = (r, g, b, 0)
        elif brightness < 60:
            alpha = int((brightness - 15) / 45 * 255)
            pixels[x, y] = (r, g, b, alpha)

img.save(output_path, "PNG")
print(f"Saved to {output_path}")
