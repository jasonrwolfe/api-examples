# API Examples

Python examples for interacting with APIs.

## Suppressions

### List Image Suppressions

`apis/suppressions/list_image_suppressions.py`

Lists image vulnerability suppression records matching a specified image name.

### Usage

```bash
python3 apis/suppressions/list_image_suppressions.py <image>
```

Example:

```bash
python3 apis/suppressions/list_image_suppressions.py amazonlinux
```

## Requirements

- Python 3
- requests
- python-dotenv

## Installation

Clone the repository and install the required Python packages:

```bash
pip3 install -r requirements.txt
```

## Configuration

The examples require the following environment variables:

- `API_KEY` - API key used for authentication
- `API_SECRET` - API secret used to sign authentication requests
- `HOST` - API hostname
- `AUTH_HOST` - Authentication API hostname

### Using a `.env` File

Copy the example environment file:

```bash
cp .env.example .env
```

Update `.env` with the appropriate values:

```text
API_KEY=your_api_key
API_SECRET=your_api_secret
HOST=your_api_host
AUTH_HOST=your_auth_host
```

The `.env` file contains credentials and should not be committed to the repository.

### Using Environment Variables

Alternatively, export the variables in your shell:

```bash
export API_KEY="your_api_key"
export API_SECRET="your_api_secret"
export HOST="your_api_host"
export AUTH_HOST="your_auth_host"
```

Then run the example:

```bash
python3 apis/suppressions/list_image_suppressions.py amazonlinux
```

## Security

Do not commit API keys, API secrets, `.env` files, or other credentials to the repository. The repository's `.gitignore` should exclude `.env`.