# Memory Forensics Triage Tool

An open-source memory forensics triage tool built with Python, Volatility 3, and YARA for automated malware and ransomware detection from RAM dumps.

## Features
- Automated execution of 6 Volatility 3 forensics plugins
- YARA scanning against 400+ real malware signatures
- Auto severity scoring — CRITICAL, HIGH, MEDIUM, LOW
- Professional HTML triage report generated automatically

## Tools Used
- Python 3
- Volatility 3
- YARA
- MemLabs memory images for testing

## How to Use
1. Install dependencies: `pip install volatility3 yara-python`
2. Place your memory image file in a known location
3. Update the `MEMORY_IMAGE` path in `triage.py`
4. Run: `python triage.py`
5. Open `report.html` in your browser

## Tested Against
- MemLabs Lab 1 memory image
- Detected: APT1, PlugX, Ursnif, Kovter, SpyEye, Cerberus and more

## Academic Context
Developed as part of CET3011 Computing Project — University of Sunderland.
Topic: Open-source Memory Forensics for Malware/Ransomware Triage.
