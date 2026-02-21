# BIP-39 Seedphrase Generator 🌱

A simple offline tool to generate valid BIP-39 mnemonics. This project is primarily designed as a companion utility to provide test data for the **BIP-39 Seedphrase Obfuscator**.

## 🚀 Features

- **Standard Compliance**: Generates mnemonics that follow the full BIP-39 specification.
- **Configurable Length**: Support for both 12-word (128-bit entropy) and 24-word (256-bit entropy) phrases.
- **Secure Randomness**: Uses the operating system's Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) via Python's `secrets` module.
- **Valid Checksums**: Automatically calculates and appends the correct SHA-256-based checksum to every phrase.
- **Batch Export**: Generate multiple phrases at once and save them directly to `frases.txt`.
- **Zero Dependencies**: 100% pure Python 3 using only the standard library.

## 🛠 Prerequisites

- **Python 3.x**
- **Wordlist**: Requires the `bip39.txt` dictionary in the same directory.

## 🖥 Usage

1. **Launch the application**:
   ```bash
   python3 bip39_generator.py
   ```
2. **Configure Generation**:
   - Choose between **12** or **24** words.
   - Enter the number of phrases you wish to generate.
3. **Generate**: Click the button to display the phrases in the log and save them to `frases.txt`.

## 🧬 Technical Process

1. **Entropy**: Generates 128 or 256 bits of random data.
2. **Checksum**: Computes `SHA-256(entropy)` and takes the first `ENT/32` bits.
3. **Encoding**: Combines entropy and checksum, then maps 11-bit chunks to words from the BIP-39 English list.

## 🛡 Security Note

While this tool uses secure randomness, always exercise caution when generating keys for actual funds. Use on an offline, clean system for maximum security.
