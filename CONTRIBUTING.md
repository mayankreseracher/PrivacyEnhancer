# Contributing to TrackerControl PC & Linux

Thank you for your interest in contributing to TrackerControl PC! We welcome pull requests, bug reports, threat signature submissions, and documentation improvements.

## Development Setup

### Windows
1. Clone the repository:
   ```powershell
   git clone https://github.com/TrackerControl/trackercontrol-pc.git
   cd trackercontrol-pc
   ```
2. Install Python 3.10+ dependencies:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Run the development server:
   ```powershell
   python main.py
   ```

### Linux
1. Clone the repository:
   ```bash
   git clone https://github.com/TrackerControl/trackercontrol-pc.git
   cd trackercontrol-pc
   ```
2. Run the automated launcher:
   ```bash
   chmod +x start_trackercontrol.sh
   sudo ./start_trackercontrol.sh
   ```

## Compiling Standalone Releases

* **Windows Executable**:
  ```powershell
  pyinstaller TrackerControl.spec --noconfirm
  ```
* **Linux Standalone Binary & Packages**:
  ```bash
  ./packaging/package_linux_releases.sh
  ```

## Threat Signature Submissions
To add new trackers or telemetry domains:
1. Edit `data/trackers.json`.
2. Ensure domain patterns and company metadata conform to standard Exodus Privacy / Disconnect schemas.
3. Submit a pull request.

## License
By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
