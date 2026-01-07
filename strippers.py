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
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta

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
    
    # Create . noindex file to prevent Spotlight indexing
    noindex_file = output_dir / ".noindex"
    noindex_file.touch(exist_ok=True)
    
    return output_dir


def strip_metadata(file_path: Path, output_dir: Path) -> bool:
    """Strip all metadata and hide file system metadata, keep only custom PNG text."""
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
            
            # Add ONLY custom metadata - nothing else
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("Source", "NGGUNGLYDNGRAADYNGMYCNGSGNGTALAHY")
            metadata.add_text("Comment", "Hello, what is it that you are looking for exactly? https://www.youtube.com/watch?v=fogKzeeVXDw&list=RDfogKzeeVXDw&start_radio=1")
            metadata.add_text("Description", "What you are hoping to find is not here. https://www.google.com/search?sca_esv=7ad34c0762c8b01c&udm=2&fbs=AIIjpHw2KGh6wpocn18KLjPMw8n5Yp8-1M0n6BD6JoVBP_K3fXXvA3S3XGyupmJLMg20um-mJAeO36stiqcDeSp1syInqJqhSijxtY18VJnNswqZEIqIPXL38MAteWnp4wS6uPmuMpOhUlhdP9rbJwptoX38hedzCJMh4q4oNw2kfdRn5MHw26aduF_c8rKmrLVGeF2Q5T_7&q=spongegar&sa=X&ved=2ahUKEwiYhre71viRAxXv1wIHHbxuBXEQtKgLegQIEhAB&biw=1440&bih=714&dpr=2#sv=CAMSVhoyKhBlLUtkejF4TVhRWl81X05NMg5LZHoxeE1YUVpfNV9OTToOQUl3TEtsbGx6enFjLU0gBCocCgZtb3NhaWMSEGUtS2R6MXhNWFFaXzVfTk0YADABGAcg9cWVxQUwAkoKCAIQAhgCIAIoAg")
            
            # Save with custom metadata, no optimization to preserve text chunks
            clean_img.save(output_path, "PNG", pnginfo=metadata, optimize=False)
        
        # === AGGRESSIVE METADATA NULLIFICATION ===
        
        # 1. Reset ALL filesystem timestamps
        
        # Define EDT (UTC-4)
        edt = timezone(timedelta(hours=-4))
        
        # Convert to Unix timestamp
        # Start:  August 18, 1969 09:00:00 -0400 (UTC: 13:00:00)
        # End:   August 18, 1969 11:15:00 -0400 (UTC: 15:15:00)
        start_time = -11790000
        end_time = -11781900
        
        try:
            # Use start time for access time, end time for modification time
            os. utime(output_path, (start_time, end_time))
        except:
            pass
        
        # 2. Strip ALL extended attributes
        try:
            subprocess.run(['xattr', '-c', str(output_path)],
                          capture_output=True, check=False, timeout=5)
        except:
            pass
        
        # 3. Clear creation date (requires SetFile from Xcode Command Line Tools)
        try:
            # Set creation date to August 18, 1969 09:00:00
            subprocess.run(['SetFile', '-d', '08/18/1969 09:00:00', str(output_path)],
                          capture_output=True, check=False, timeout=5)
        except:
            pass
            
        # 4. Force correct modification time with touch
        try:
            # Set to August 18, 1969 11:15:00
            subprocess.run(['touch', '-t', '196908181115.00', str(output_path)],
                          capture_output=True, check=False, timeout=5)
        except:
            pass
        
        # 5. Tell Spotlight to never index this file
        try:
            subprocess.run(['mdimport', '-d', '3', str(output_path)],
                          capture_output=True, check=False, timeout=5)
        except:
            pass
        
        # 6. Remove file from Spotlight index if it was indexed
        try:
            subprocess.run(['mdutil', '-E', str(output_path)],
                          capture_output=True, check=False, timeout=5)
        except:
            pass
        
        print(f"✓ {file_path.name} → cleaned/{output_path.name}")
        return True
        
    except Exception as e:
        print(f"✗ {file_path.name}: {e}")
        return False


def disable_spotlight_indexing(output_dir: Path):
    """Aggressively disable Spotlight indexing on the output directory."""
    print("\n🔒 Disabling Spotlight indexing on output folder...")
    
    # Add to Spotlight exclusion list
    try:
        subprocess.run([
            'sudo', 'mdutil', '-i', 'off', str(output_dir)
        ], capture_output=True, check=False, timeout=10)
        print("   ✓ Disabled indexing")
    except:
        print("   ⚠ Could not disable indexing (may need sudo)")
    
    # Erase any existing index
    try:
        subprocess. run([
            'sudo', 'mdutil', '-E', str(output_dir)
        ], capture_output=True, check=False, timeout=10)
        print("   ✓ Erased existing index")
    except:
        pass
    
    # Kill Spotlight daemon to force reload
    try:
        subprocess. run(['sudo', 'killall', 'mds'],
                      capture_output=True, check=False, timeout=5)
        print("   ✓ Restarted Spotlight daemon")
    except:
        pass


def main():
    # Supported image extensions
    extensions = {'.png', '.jpg', '.jpeg', '.heic', '.webp'}
    
    # Ensure output folder exists
    print("🔧 Setting up output folder...")
    output_dir = ensure_noindex_folder()
    
    # Determine what to process
    if len(sys. argv) > 1:
        # Files passed as arguments (drag and drop)
        files = [Path(f) for f in sys.argv[1:] if Path(f).suffix.lower() in extensions]
    else:
        # Process current directory
        files = [f for f in Path('.').iterdir() if f.suffix.lower() in extensions and '_clean' not in f.stem]
    
    if not files:
        print("No images found.  Place this script in a folder with images or drag images onto it.")
        return
    
    print(f"Processing {len(files)} image(s)...\n")
    
    success = sum(1 for f in files if strip_metadata(f, output_dir))
    
    # Disable Spotlight on the output directory
    disable_spotlight_indexing(output_dir)
    
    print(f"\n✅ Done! Cleaned {success}/{len(files)} images.")
    print(f"📁 Files saved to: ~/Desktop/cleaned/")
    print(f"\n🔍 To verify metadata is hidden:")
    print(f"   mdls ~/Desktop/cleaned/*_clean.png")
    print(f"   (Should show mostly (null) values)")
    print(f"\n🔍 To see custom metadata (YouTube link):")
    print(f"   exiftool ~/Desktop/cleaned/*_clean.png")
    print(f"   (Should show Source, Comment, Description)")
    print(f"\n⚠️  If mdls STILL shows metadata:")
    print(f"   1. System Settings > Siri & Spotlight > Spotlight Privacy")
    print(f"   2. Click '+' and add:  ~/Desktop/cleaned")
    print(f"   3. Run: sudo mdutil -i off ~/Desktop/cleaned")
    print(f"   4. Run: sudo mdutil -E ~/Desktop/cleaned")
    print(f"   5. Run: sudo killall mds")


if __name__ == "__main__":
    main()
