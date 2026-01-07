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
from datetime import datetime

try:
    from PIL import Image
    from PIL import PngImagePlugin
except ImportError:
    print("Installing required dependency (Pillow)...")
    os.system(f"{sys.executable} -m pip install Pillow")
    from PIL import Image
    from PIL import PngImagePlugin


def strip_metadata(file_path:  Path) -> bool:
    """Strip all metadata from an image file."""
    try:
        output_path = file_path.parent / f"{file_path.stem}_clean.png"
        
        with Image.open(file_path) as img:
            # Convert to RGB if necessary (handles HEIC, etc.)
            if img.mode in ('RGBA', 'LA', 'P'):
                clean_img = Image.new('RGBA', img.size)
                clean_img.paste(img)
            else:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                clean_img = Image.new('RGB', img.size)
                clean_img.paste(img)
            
            # Add custom metadata
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("Source", "https://www.youtube.com/watch?v=fogKzeeVXDw&list=RDfogKzeeVXDw&start_radio=1")
            metadata.add_text("Comment", "Hello, what is it that you are looking for exactly?")
            metadata.add_text("Description", "What you are hoping to find is not here.")
            
            # Save with custom metadata
            clean_img.save(output_path, "PNG", pnginfo=metadata, optimize=False)
        
        # Reset file system timestamps to generic date
        generic_time = datetime(2020, 1, 1, 0, 0, 0).timestamp()
        os.utime(output_path, (generic_time, generic_time))
        
        print(f"✓ {file_path.name} → {output_path.name}")
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
