Forensics software. 

For QRcodechecker.py , install everything into source ~/.venv/bin/activate first 
pip install --upgrade pip
pip install pyzbar opencv-python-headless Pillow numpy qrcode qreader pyzxing \
    python-barcode yara-python requests python-magic-bin scikit-image imageio \
    scipy tldextract cryptography colorama termcolor segno

# Essential QR/Image Processing
pip3 install pyzbar opencv-python-headless Pillow qrcode qreader

# Additional decoders
pip3 install pyzxing python-barcode segno

# Analysis tools
pip3 install yara-python requests python-magic-bin

# Scientific/Image processing
pip3 install scikit-image imageio scipy

# Network/Security
pip3 install tldextract cryptography

# Optional but useful
pip3 install colorama termcolor

brew install zbar

# Install libdmtx for DataMatrix codes
brew install libdmtx dmtx-utils

# Install other tools the script references
brew install imagemagick tesseract qrencode

# Install GNU parallel for resource-safe parallel execution (prevents fork exhaustion)
brew install parallel

and run the software with source ~/.venv/bin/activate
Enter: source ~/.venv/bin/activate
then
Enter: bash ~/desktop/QRcodechecker.sh ~/Desktop/(QRCODE.jpg/.jpeg/etc)


All are drafts, all are pretty straight forward. The aim is a theme related "Everything in everything" per detection software. Could I earn from this? Sure but this is a hobby, I have other things I want to do to earn a living.
If this software is free for the public to use. Why? cyber criminals (regardless of the legitimacy of the institution, corporation etc) will be less likely to engage in unlawful cyber activity if everyone has stuff like this at their disposal. 
There really isn't a limit to the size an scale of what this software aims to detect and do. Detection capabilities ranges from petty cyber crime to whatever the highest you can conceptualize.
It's all theoretical, and unless you are 100% certain of a result, don't act on it. For this reason be careful when using some of these detection softwares. They are research based and are not certified in any sense. 
However, sometimes you may absolutely get a verifiable and admissible result, just double / infinity check first, consult a cyber security business about it etc.
IP_ID_checker.py and NetCapAnalyzer.sh are pretty rock solid. Same with OMGcablechecker.sh .
I am a beginner still. Only started in October last year.

Given the state of things, it is best to ask for an NDA to be signed prior to approaching anyone external from law enforcement to verify these things. I have one for my research methods as I also do research and development for other things as well. 

Enjoy.
