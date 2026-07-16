# Contributing to N2-NG

Thanks for taking the time to contribute! This project is built by pentesters, for pentesters — your input matters.

## How to Contribute

### Reporting Bugs

Open an issue with:
- Your Kali / Debian version (`lsb_release -a`)
- Python version (`python3 --version`)
- Wireless adapter chipset (`lsusb` or `iw dev`)
- What you expected vs. what happened
- Steps to reproduce
- Screenshot if it's a GUI issue

### Feature Requests

Open an issue with the `enhancement` label. Describe:
- What the feature should do
- Why it helps (save clicks? prevent mistakes?)
- Mockup or description of expected UI flow

### Pull Requests

1. Fork the repo and create a branch: `git checkout -b feature/your-thing`
2. Make your changes
3. Run tests: `python3 -m pytest test_helpers.py test_ui.py -v`
4. Make sure your code follows PEP 8 (run `flake8 src/`)
5. Submit the PR with a clear description

### Code Style

- Follow PEP 8
- Use type hints for new functions
- Keep tkinter logic in `main.py`, business logic in `capture.py`/`scanner.py`/`utils.py`
- Add docstrings for public functions

### Commit Messages

Keep them descriptive:
- `feat: add WPA3 detection in scan table`
- `fix: resolve channel hop freeze on RTL8812AU`
- `docs: update install steps for ARM64`

## Development Setup

```bash
git clone https://github.com/KiMiGuel/n2-ng.git
cd n2-ng
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 n2_ng.py
```

## Questions?

Drop an issue or reach out. We're friendly.
