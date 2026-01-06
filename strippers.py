#!/usr/bin/env python3
"""
Screenshot Metadata Stripper
Removes all EXIF/metadata from images. 
Run  mdls ~/desktop/(Path/to/file.jpg) before and after.
~/venv/bin/python3 ~/Desktop/strippers.py ~/Desktop/Path/to/file.jpg
"""

import sys
from pathlib import Path
from PIL import Image


def strip_metadata(file_path:  Path) -> bool:
    """Strip all metadata from an image file."""
    try:
        output_path = file_path.parent / f"{file_path.stem}_clean. png"
        
        with Image.open(file_path) as img:
            # Convert to RGB/RGBA and create completely new image
            if img.mode == 'RGBA' or (img.mode == 'P' and 'transparency' in img.info):
                img = img.convert('RGBA')
                clean_img = Image.new('RGBA', img.size, (255, 255, 255, 0))
            else:
                img = img.convert('RGB')
                clean_img = Image.new('RGB', img.size, (255, 255, 255))
            
            # Copy only pixel data
            clean_img. paste(img)
            
            # Save with no metadata
            clean_img.save(output_path, "PNG", pnginfo=None)
        
        print(f"✓ {file_path.name} → {output_path.name}")
        return True
    except Exception as e:
        print(f"✗ {file_path.name}: {e}")
        return False


def main():
    extensions = {'.png', '.jpg', '. jpeg', '.heic', '.webp', '.gif', '.tiff'}
    
    if len(sys.argv) > 1:
        files = [Path(f) for f in sys.argv[1:] if Path(f).suffix.lower() in extensions]
    else:
        files = [f for f in Path('.').iterdir() if f.suffix.lower() in extensions and '_clean' not in f.stem]
    
    if not files:
        print("No images found.")
        return
    
    print(f"Processing {len(files)} image(s)...\n")
    
    for f in files:
        strip_metadata(f)


if __name__ == "__main__":
    main()
