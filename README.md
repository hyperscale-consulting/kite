# Kite - AWS Security Assessment CLI

Kite is a command-line interface tool designed to help security professionals perform AWS security assessments efficiently. It provides a suite of commands to analyze and assess AWS security configurations and best practices.

## Features

- AWS security assessment
- IAM configuration analysis
- Security group and network ACL validation
- S3 bucket security checks
- AWS best practices validation
- Automated security checks

## Installation

```bash
pip install kite
```

## Usage

```bash
kite --help
kite assess -r us-east-1  # Assess AWS resources in us-east-1
```

## Development

### Prerequisites

- Python 3.8+
- pip
- AWS credentials configured (via AWS CLI or environment variables)

### Setup Development Environment

1. Clone the repository:
```bash
git clone https://github.com/yourusername/kite.git
cd kite
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
