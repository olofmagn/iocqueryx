# IocQueryX - IOC Query Generator
A simple python script that generate platform-specific queries (e.g., AQL, Elasticsearch, Defender) from input lists of IP addresses, domain names, or file hashes to identify first point of contact.

## Features

### Platform-Specific Query Generation
This tool supports generating queries for the following platforms:

- AQL (IBM QRadar).
- Elastic (ECS).
- Microsoft Defender (KQL).

### Input Support
- Accepts IP addresses.
- Accepts domain names.
- Accepts file hashes.
- Accepts filtering options to iterate data more efficent.

### Flexible Hash Mapping
- Automatically maps hash types to platform-specific field names.
- Supported hash types: `md5`, `sha1`, `sha256`.

### Filtering Options
#### Qradar AQL:
- `qid` filter.
- `LAST` keyword filter.
#### Elastic (ECS):
- `event.action` filter.
- `@timestamp` filter.

The values are normally defined by the implementer.

### Easy Input Handling
- Reads all possible files
- Parses only the first field per line (e.g., IP, domain, or hash)
- Each line shall include comma-separated fields, but only the first field is index (e.g., the IP or domain). 

See example structure below:

```bash
185.200.85.137,443,Sweden --> ip
evil.com, Sweden --> domain
d41d8cd98f00b204e9800998ecf8427e, Sweden --> hash
```
## File structure
```
.
├── LICENSE
├── pictures
│   ├── app-in-use.png
│   └── app.png
├── README.md
├── src
│   ├── gui.py
│   ├── __init__.py
│   └── main.py
├── testips.txt
└── utils
    ├── configuration.py
    ├── generate_queries.py
    └── __init__.py

```
## Usage
This tool supports two modes of operation:

- **GUI Mode** – Interactive interface for building and generating queries.
- **CLI Mode** – Command-line usage for automation and scripting.

Choose the mode that fits your workflow. Detailed instructions for each are provided below.
###  GUI
```python3
python3 -m src.main
```

```
  ___            ___                       __  __
 |_ _|___   ___ / _ \ _   _  ___ _ __ _   _\ \/ /
  | |/ _ \ / __| | | | | | |/ _ \ '__| | | |\  / 
  | | (_) | (__| |_| | |_| |  __/ |  | |_| |/  \ 
 |___\___/ \___|\__\_\\__,_|\___|_|   \__, /_/\_\
                                      |___/      

Welcome to the application!
Enjoy using the app, and feel free to share any feature requests or feedback!
Version: 1.0.0 olofmagn

? Choose interface mode: (Use arrow keys)
 » GUI
   CLI
   EXIT
```

<img src="pictures/app.png" alt="qradar gui" width="400"/>

Example usage of an input file of IP addresses, mode: aql and qid.

<img src="pictures/app-in-use.png" alt="app in use" width="400"/>

### CLI
AQL Query (IP) with QID-number:
```python3
python3 -m src.main -i sample.txt -m aql -t ip -q 20257872
```

Elastic Query (Hashes):
```python3
python3 -m src.main -i sample.txt -m es -t hash -ht sha1
```

Defender Query (Domains):
```python3
python3 -m src.main -i sample.txt -m defender -t domain
```

## License
This project is open-source and licensed under the MIT License. See the LICENSE file for details.
