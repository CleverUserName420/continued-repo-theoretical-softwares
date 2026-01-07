#!/usr/bin/env python3
"""
Screenshot Metadata Stripper
Drag and drop images or place this script in a folder with images.     
Automatically strips all EXIF/metadata from PNG, JPG, and HEIC files.  
Run  mdls ~/desktop/(Path/to/file.jpg) before and after.# Install exiftool if needed
(If it's not working)
# Disable Spotlight indexing on your data volume
sudo mdutil -i off /System/Volumes/Data

# Delete all existing Spotlight indexes
sudo mdutil -E /System/Volumes/Data

# Kill and restart Spotlight daemon
sudo killall mds

# Wait 10 seconds for it to settle
sleep 10

# Verify it's disabled
mdutil -s /System/Volumes/Data
(To re-activate if needed)
# Re-enable Spotlight indexing on your data volume
sudo mdutil -i on /System/Volumes/Data

# Restart Spotlight daemon to begin re-indexing
sudo killall mds

# Wait for it to restart
sleep 5

# Verify it's enabled
mdutil -s /System/Volumes/Data

# Check indexing status (should show "Indexing enabled.")
echo "Spotlight status:"
sudo mdutil -a -s

# Trigger re-indexing of your home directory
sudo mdutil -E /System/Volumes/Data
--------------------------------------
Checking can be done with exiftool: brew install exiftool
# Check the cleaned file
exiftool ~/Desktop/original_image_clean. png
~/venv/bin/python3 ~/Desktop/strippers.py ~/Desktop/Path/to/file.jpg
exfiltool with show the yt details.   
e. g
<redacted> ~ % mdls ~/desktop/0_clean.png             
kMDItemFSContentChangeDate = (null)
kMDItemFSCreationDate      = (null)
kMDItemFSCreatorCode       = ""
kMDItemFSFinderFlags       = (null)
kMDItemFSHasCustomIcon     = (null)
kMDItemFSInvisible         = 0
kMDItemFSIsExtensionHidden = (null)
kMDItemFSIsStationery      = (null)
kMDItemFSLabel             = (null)
kMDItemFSName              = (null)
kMDItemFSNodeCount         = (null)
kMDItemFSOwnerGroupID      = (null)
kMDItemFSOwnerUserID       = (null)
kMDItemFSSize              = (null)
kMDItemFSTypeCode          = ""
<redacted> ~ % exiftool ~/Desktop/0_clean.png               
ExifTool Version Number         :  13.44
File Name                       : 0_clean.png
Directory                       :  /Users/<redacted>/Desktop
File Size                       : 1588 kB
File Modification Date/Time     : <redacted>
File Access Date/Time           :  <redacted>
File Inode Change Date/Time     : <redacted>
File Permissions                :  -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1072
Image Height                    :  1430
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       :  Noninterlaced
Source                          : https://www.youtube.com/watch?v=fogKzeeVXDw&list=RDfogKzeeVXDw&start_radio=1
Comment                         : Hello, what is it that you are looking for exactly? 
Description                     :  What you are hoping to find is not here. https://www.google.com/search?sca_esv=7ad34c0762c8b01c&udm=2&fbs=AIIjpHw2KGh6wpocn18KLjPMw8n5Yp8-1M0n6BD6JoVBP_K3fXXvA3S3XGyupmJLMg20um-mJAeO36stiqcDeSp1syInqJqhSijxtY18VJnNswqZEIqIPXL38MAteWnp4wS6uPmuMpOhUlhdP9rbJwptoX38hedzCJMh4q4oNw2kfdRn5MHw26aduF_c8rKmrLVGeF2Q5T_7&q=spongegar&sa=X&ved=2ahUKEwiYhre71viRAxXv1wIHHbxuBXEQtKgLegQIEhAB&biw=1440&bih=714&dpr=2#sv=CAMSVhoyKhBlLUtkejF4TVhRWl81X05NMg5LZHoxeE1YUVpfNV9OTToOQUl3TEtsbGx6enFjLU0gBCocCgZtb3NhaWMSEGUtS2R6MXhNWFFaXzVfTk0YADABGAcg9cWVxQUwAkoKCAIQAhgCIAIoAg
Image Size                      : 1072x1430
Megapixels                      : 1.5
"""

import os
import sys
import subprocess
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


def ensure_noindex_folder():
    """Create and configure a folder that Spotlight will never index."""
    output_dir = Path. home() / "Desktop" / "cleaned"
    
    # Remove folder if it exists to start fresh
    if output_dir.exists():
        try:
            import shutil
            shutil.rmtree(output_dir)
        except:
            pass
    
    # Create fresh folder
    output_dir.mkdir(exist_ok=True)
    
    # Create multiple marker files (belt and suspenders approach)
    markers = [
        ".metadata_never_index",
        ".metadata_never_index_unless_rootfs",
        ".noindex",
        ".nosearch"
    ]
    
    for marker in markers:
        marker_file = output_dir / marker
        marker_file.touch(exist_ok=True)
    
    # Try to tell Spotlight to ignore this folder via command line
    try:
        # Delete any existing index for this folder
        subprocess.run(['sudo', 'mdutil', '-E', str(output_dir)],
                      capture_output=True, check=False, timeout=5)
    except:
        pass
    
    try:
        # Kill and restart Spotlight to pick up changes
        subprocess.run(['sudo', 'killall', 'mds'],
                      capture_output=True, check=False, timeout=5)
    except:
        pass
    
    return output_dir


def strip_metadata(file_path: Path, output_dir: Path) -> bool:
    """Strip all metadata from an image file."""
    try:
        output_path = output_dir / f"{file_path.stem}_clean.png"
        
        with Image.open(file_path) as img:
            # Convert to RGB if necessary (handles HEIC, etc.)
            if img. mode in ('RGBA', 'LA', 'P'):
                clean_img = Image.new('RGBA', img.size)
                clean_img.paste(img)
            else:
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                clean_img = Image.new('RGB', img.size)
                clean_img.paste(img)
            
            # Add custom metadata
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("Source", "NGGUNGLYDNGRAADYNGMYCNGSGNGTALAHY")
            metadata.add_text("Comment", "Hello, what is it that you are looking for exactly? https://www.youtube.com/watch?v=fogKzeeVXDw&list=RDfogKzeeVXDw&start_radio=1")
            metadata.add_text("Description", "What you are hoping to find is not here. https://www.google.com/search?sca_esv=7ad34c0762c8b01c&udm=2&fbs=AIIjpHw2KGh6wpocn18KLjPMw8n5Yp8-1M0n6BD6JoVBP_K3fXXvA3S3XGyupmJLMg20um-mJAeO36stiqcDeSp1syInqJqhSijxtY18VJnNswqZEIqIPXL38MAteWnp4wS6uPmuMpOhUlhdP9rbJwptoX38hedzCJMh4q4oNw2kfdRn5MHw26aduF_c8rKmrLVGeF2Q5T_7&q=spongegar&sa=X&ved=2ahUKEwiYhre71viRAxXv1wIHHbxuBXEQtKgLegQIEhAB&biw=1440&bih=714&dpr=2#sv=CAMSVhoyKhBlLUtkejF4TVhRWl81X05NMg5LZHoxeE1YUVpfNV9OTToOQUl3TEtsbGx6enFjLU0gBCocCgZtb3NhaWMSEGUtS2R6MXhNWFFaXzVfTk0YADABGAcg9cWVxQUwAkoKCAIQAhgCIAIoAg")
            
            # Save with custom metadata
            clean_img.save(output_path, "PNG", pnginfo=metadata, optimize=False)
        
        # Reset file system timestamps to generic date
        generic_time = datetime(2020, 1, 1, 0, 0, 0).timestamp()
        os.utime(output_path, (generic_time, generic_time))
        
        # Strip extended attributes (macOS quarantine flags, etc.)
        try:
            subprocess.run(['xattr', '-c', str(output_path)],
                          capture_output=True, check=False)
        except:
            pass
        
        # Try to reset birth time on macOS (requires SetFile from Xcode tools)
        try:
            subprocess.run(['SetFile', '-d', '01/01/2020 00:00:00',
                          str(output_path)], capture_output=True, check=False)
        except:
            pass
        
        # Aggressively prevent indexing of this specific file
        try:
            subprocess.run(['mdimport', '-d', '3', str(output_path)],
                          capture_output=True, check=False)
        except:
            pass
        
        print(f"✓ {file_path.name} → ~/Desktop/cleaned/{output_path.name}")
        return True
    except Exception as e:
        print(f"✗ {file_path.name}:  {e}")
        return False


def main():
    # Supported image extensions
    extensions = {'. png', '.jpg', '.jpeg', '.heic', '.webp'}
    
    # Ensure output folder exists and is configured to avoid indexing
    print("🔧 Setting up non-indexed output folder...")
    output_dir = ensure_noindex_folder()
    
    # Determine what to process
    if len(sys.argv) > 1:
        # Files passed as arguments (drag and drop)
        files = [Path(f) for f in sys.argv[1:] if Path(f).suffix.lower() in extensions]
    else:
        # Process current directory
        files = [f for f in Path('.').iterdir() if f.suffix.lower() in extensions and '_clean' not in f.stem]
    
    if not files:
        print("No images found.   Place this script in a folder with images or drag images onto it.")
        return
    
    print(f"Processing {len(files)} image(s)...\n")
    
    success = sum(1 for f in files if strip_metadata(f, output_dir))
    
    print(f"\n✓ Done! Cleaned {success}/{len(files)} images.")
    print(f"\n📁 Files saved to: ~/Desktop/cleaned/")
    print(f"\n⚠️  If mdls still shows metadata, you must manually:")
    print(f"   1. Open System Settings > Siri & Spotlight > Spotlight Privacy")
    print(f"   2. Click '+' and add:  ~/Desktop/cleaned")
    print(f"   3. Run: sudo mdutil -E / && sudo killall mds")
    print(f"\n💡 To verify: mdls ~/Desktop/cleaned/*_clean.png")


if __name__ == "__main__":
    main()
