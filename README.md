# API Examples

Python examples for interacting with APIs.

## Suppressions

### List Image Suppressions

`suppressions/list_image_suppressions.py`

Lists image suppression records matching a specified image name.

#### Usage

```bash
python3 suppressions/list_image_suppressions.py <image>
```

Example:

```bash
python3 suppressions/list_image_suppressions.py amazonlinux
```

### List Image Vulnerability Suppressions

`suppressions/list_image_vuln_suppressions.py`

Lists acknowledged image vulnerabilities and vulnerability suppressions matching a specified image name.

The script includes acknowledged parent vulnerabilities and referenced CVEs. If a parent vulnerability is acknowledged, its referenced vulnerabilities are also included.

An optional registry can be specified to limit results to a specific registry.

#### Usage

```bash
python3 suppressions/list_image_vuln_suppressions.py <image> [registry]
```

Examples:

Search across registries:

```bash
python3 suppressions/list_image_vuln_suppressions.py amazonlinux
```

Search within a specific registry:

```bash
python3 suppressions/list_image_vuln_suppressions.py amazonlinux "Docker Hub"
```

Another registry example:

```bash
python3 suppressions/list_image_vuln_suppressions.py amazonlinux "Ad Hoc Scans"
```

## Requirements

- Python 3
- `requests`
- `python-dotenv`

## Installation

Clone the repository and install the required Python packages:

```bash
pip3 install -r requirements.txt
```

## Configuration

Create a `.env` file containing the required API configuration:

```dotenv
API_KEY=<api-key>
API_SECRET=<api-secret>
HOST=<api-host>
AUTH_HOST=<authentication-host>
```

The scripts load these values from the environment using `python-dotenv`.

> **Note:** Do not commit the `.env` file or API credentials to source control.