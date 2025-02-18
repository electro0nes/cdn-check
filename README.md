# Cdn-Check

**Cdn-Check** is a Python tool to check if an IP address is behind a CDN using a list of known CDN provider ranges.

## Features

- Supports single IP (`-i`) and bulk IP processing from a file (`-l`)
- Retrieves CDN IP ranges from multiple sources defined in a YAML file
- Supports JSON, XML, CSV, and plain text formats
- Multi-threading support for faster processing (`--threads`)
- Output results to CLI (default) or file (`-o`)
- Silent mode (`--silent`) to suppress banner output

## Installation

```bash
git clone https://github.com/moeinerfanian/cdn-check.git
cd cdn-check
pip3 install -r requirements.txt
```

## Usage

```bash
python cdn-check.py -i <IP> 
python cdn-check.py -l ips.txt --threads 5 -o results.txt
```

### Arguments:

| Flag          | Description |
|--------------|-------------|
| `-i` / `--ip` | Single IP to check |
| `-l` / `--list` | File containing list of IPs |
| `-p` / `--providers` | YAML file with CDN provider sources |
| `--silent` | Suppress banner output |
| `--threads` | Number of threads (default: 1) |
| `-o` / `--output` | Output file (default: CLI output) |

## Example Provider YAML

```yaml
Request:
  - https://www.cloudflare.com/ips-v4
Read:
  - https://digitalocean.com/geo/google.csv
```

## License
MIT License

## Author
**Moein Erfanian (Electro0ne)**  
GitHub: [moeinerfanian](https://github.com/moeinerfanian)
Cut-Cdn : [ImAyrix](https://github.com/ImAyrix/cut-cdn/)
