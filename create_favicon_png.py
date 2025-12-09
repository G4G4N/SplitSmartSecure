"""
Script to create PNG favicon from design
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_favicon_png():
    """Create a PNG favicon (32x32 and 16x16)"""
    sizes = [32, 16]
    
    for size in sizes:
        # Create image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw shield shape (simplified)
        shield_points = [
            (size * 0.22, size * 0.12),
            (size * 0.22, size * 0.48),
            (size * 0.5, size * 0.88),
            (size * 0.78, size * 0.48),
            (size * 0.78, size * 0.12),
        ]
        
        # Draw shield with gradient effect (purple)
        draw.polygon(shield_points, fill=(99, 102, 241, 255))  # #6366f1
        draw.polygon(shield_points, outline=(255, 255, 255, 255), width=max(1, size//16))
        
        # Draw diamond/split symbol (green)
        diamond_points = [
            (size * 0.5, size * 0.32),
            (size * 0.38, size * 0.5),
            (size * 0.5, size * 0.68),
            (size * 0.62, size * 0.5),
        ]
        draw.polygon(diamond_points, fill=(16, 185, 129, 255))  # #10b981
        
        # Draw dollar sign
        try:
            # Try to use a font
            font_size = max(8, size // 2)
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            # Fallback to default font
            font = ImageFont.load_default()
        
        # Draw $ symbol
        text = "$"
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_x = (size - text_width) // 2
        text_y = (size - text_height) // 2 - size // 16
        
        draw.text((text_x, text_y), text, fill=(255, 255, 255, 255), font=font)
        
        # Draw small lock icon at bottom
        lock_y = size * 0.78
        lock_size = max(2, size // 8)
        draw.ellipse([size * 0.5 - lock_size, lock_y - lock_size, 
                     size * 0.5 + lock_size, lock_y + lock_size], 
                    fill=(255, 255, 255, 100))
        
        # Save PNG
        output_path = f"static/images/favicon_{size}x{size}.png"
        img.save(output_path, 'PNG')
        print(f"✓ Created {output_path}")
        
        # Also save as favicon.png (use 32x32)
        if size == 32:
            img.save("static/images/favicon.png", 'PNG')
            print("✓ Created static/images/favicon.png")

if __name__ == "__main__":
    create_favicon_png()
    print("\n✓ Favicon PNG files created successfully!")

