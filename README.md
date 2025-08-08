# fmcos-python
Python implementation of fmcos using a PN532/PM3/pyscard
Tested on FM1208-09 with PN532 / ACR1581

## Features
- Read / write blocks and files on FM1208-09 cards
- Plain and secure messaging (MAC / ENC) helpers
- PN532 (UART/I2C/SPI), Proxmark3 (pm3 console wrapper), and PC/SC (pyscard) backends
- Command line tooling plus importable Python API

## Hardware / Software Requirements
- Python 3.9+ (virtual environment recommended)
- One supported reader:
    - PN532 breakout (Adafruit, Elechouse, etc.)
    - Proxmark3 (client installed and in PATH)
    - PC/SC compatible reader (ACR1581 or similar)
- FM1208-09 compatible smart card / token
- libusb (if required by platform), pcsc-lite on Linux for PC/SC

## Safety / Legal
Only interact with cards you own or are authorized to test. Cloning or modifying third-party credentials may be illegal.

## Contributing
1. Fork and create a feature branch.
2. Add tests for new behavior.
3. Ensure lint / type checks pass.
4. Submit a concise pull request description.
