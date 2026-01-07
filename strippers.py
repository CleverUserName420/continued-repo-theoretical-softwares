#!/usr/bin/env python3
"""
Screenshot Metadata Stripper
Drag and drop images or place this script in a folder with images. 
Automatically strips all EXIF/metadata from PNG, JPG, and HEIC files.
Run  mdls ~/desktop/(Path/to/file.jpg) before and after.
~/venv/bin/python3 ~/Desktop/strippers.py ~/Desktop/Path/to/file.jpg
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Installing required dependency (Pillow)...")
    os.system(f"{sys.executable} -m pip install Pillow")
    from PIL import Image


def strip_metadata(file_path: Path) -> bool:
    """Strip all metadata from an image file."""
    try:
        output_path = file_path.parent / f"{file_path.stem}_clean. png"
        
        with Image.open(file_path) as img:
            # Convert to RGB if necessary (handles HEIC, etc.)
            if img.mode in ('RGBA', 'LA', 'P'):
                clean_img = Image.new('RGBA', img.size)
            else:
                clean_img = Image.new('RGB', img.size)
            
            clean_img.putdata(list(img.getdata()))
            clean_img.save(output_path, "PNG")
        
        print(f"✓ {file_path.name} → {output_path. name}")
        return True
    except Exception as e:
        print(f"✗ {file_path.name}: {e}")
        return False


def main():
    # Supported image extensions
    extensions = {'.png', '.jpg', '.jpeg', '.heic', '.webp'}
    
    # Determine what to process
    if len(sys.argv) > 1:
        # Files passed as arguments (drag and drop)
        files = [Path(f) for f in sys.argv[1:] if Path(f).suffix.lower() in extensions]
    else:
        # Process current directory
        files = [f for f in Path('.').iterdir() if f.suffix.lower() in extensions and '_clean' not in f.stem]
    
    if not files:
        print("No images found.  Place this script in a folder with images or drag images onto it.")
        return
    
    print(f"Processing {len(files)} image(s)...\n")
    
    success = sum(1 for f in files if strip_metadata(f))
    
    print(f"\n✓ Done! Cleaned {success}/{len(files)} images.")


if __name__ == "__main__":
    main()
