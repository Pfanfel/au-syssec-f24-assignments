## Usage

Install the pakages from the requirements.txt

`pip install -r requirements.txt`

Create a virtual enviroment

`python -m venv venv`

Run the script in sudo mode, using the python install from the .venv

`sudo .venv/bin/python own_icmp_msg.py`


Usage:
```
ICMP Client/Server message program

positional arguments:
  {client,server}  Program mode: client or server
  destination_ip   Destination IP address (required for client mode)

options:
  -h, --help       show this help message and exit
```