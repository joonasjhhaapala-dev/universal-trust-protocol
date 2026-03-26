# Contributing to UTP

Thank you for your interest in contributing to the Universal Trust Protocol. This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/utp.git
   cd utp
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install pytest httpx
   ```

## Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Run the tests:
   ```bash
   python -m pytest tests/ -v
   ```
4. Commit your changes with a clear message
5. Push and open a pull request

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_crypto.py -v

# Run with coverage (if installed)
python -m pytest tests/ --cov=src
```

## Code Style

- Follow PEP 8 conventions
- Use type hints for function signatures
- Write docstrings for classes and public methods
- Keep functions focused and concise

## Project Structure

```
utp/
  src/
    __init__.py          # Package init
    crypto_utils.py      # Ed25519 key management, signing, token creation
    identity.py          # DID document creation and verification
    capabilities.py      # Capability-based authorization
    attestation.py       # Behavioral anomaly detection and trust scores
    revocation.py        # Credential revocation registry
    registry.py          # Entity lifecycle management
    api.py               # FastAPI routes
    main.py              # Server entry point
    demo.py              # Interactive CLI demo
    dashboard.html       # Web dashboard
  tests/
    conftest.py          # Shared fixtures
    test_crypto.py       # Cryptographic operation tests
    test_identity.py     # DID system tests
    test_capabilities.py # Capability authorization tests
    test_attestation.py  # Behavioral attestation tests
    test_revocation.py   # Revocation tests
    test_api.py          # API endpoint tests
```

## Reporting Issues

- Use GitHub Issues
- Include steps to reproduce
- Include Python version and OS
- Include relevant error messages

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if needed
- Ensure all tests pass before submitting

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
