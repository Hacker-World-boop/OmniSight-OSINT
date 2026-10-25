# Contributing to OmniSight-OSINT

Thank you for your interest in contributing to **OmniSight-OSINT**!

## How to Contribute

### 1. Fork & Clone
```bash
git clone https://github.com/MuhammadInaamKaleem/OmniSight-OSINT.git
cd OmniSight-OSINT
```

### 2. Set Up Development Environment (Linux)
```bash
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
chmod +x open_osint.py
```

### 3. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 4. Make Your Changes
- Follow the existing code style and architecture
- Add docstrings to all new functions and classes
- Use type hints for all function signatures
- Use `async`/`await` for any I/O operations
- Add new modules under `modules/` directory

### 5. Test Your Changes
```bash
# Test IP tracking
python3 open_osint.py --ip 8.8.8.8

# Test phone tracking
python3 open_osint.py --phone +14155552671

# Test username enumeration
python3 open_osint.py --username testuser

# Test with verbose logging
python3 open_osint.py --ip 1.1.1.1 --verbose
```

### 6. Submit a Pull Request
- Write a clear PR description explaining your changes
- Reference any related issues
- Ensure your code follows the project conventions

## Code Style Guidelines

- **Python 3.10+** features are encouraged
- Engineered for **Linux** platforms
- Use **Pydantic** models for all data structures
- Use **aiohttp** for async HTTP requests
- Use **Rich** for terminal output formatting
- Follow PEP 8 naming conventions
- Keep functions focused and modular

## Adding New Intelligence Modules

1. Create a new file under `modules/` (e.g., `modules/dns_tracker.py`)
2. Define Pydantic models in `modules/models.py`
3. Implement async functions following the existing pattern
4. Add display function in `open_osint.py`
5. Register CLI arguments in `parse_arguments()`
6. Update `README.md` with documentation

## Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include steps to reproduce, expected vs actual behavior
- Include your Python version and Linux distribution details

## Ethical Guidelines

> **All contributions must comply with ethical security research standards.**
> Do not submit code that performs unauthorized surveillance, illegal data collection,
> or any activity that violates privacy laws and regulations.

---

**Lead Maintainer:** Inaam Kaleem
