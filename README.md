 ▄▄▄██▀▀▀  ██████ ▓█████ ▒██   ██▒ ██▓███   ▒█████    ██████  █    ██  ██▀███  ▓█████   ██████    
   ▒██   ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▒██▒  ██▒▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒    
   ░██   ░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░  ██▒░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒███   ░ ▓██▄      
▓██▄██▓    ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██   ██░  ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒   
 ▓███▒   ▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░ ████▓▒░▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░▒████▒▒██████▒▒   
 ▒▓▒▒░   ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░   
 ▒ ░▒░   ░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░       ░ ▒ ▒░ ░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░   
 ░ ░ ░   ░  ░  ░     ░    ░    ░  ░░       ░ ░ ░ ▒  ░  ░  ░   ░░░ ░ ░   ░░   ░    ░   ░  ░  ░     
 ░   ░         ░     ░  ░ ░    ░               ░ ░        ░     ░        ░        ░  ░      ░     
                   jsexposures - Busca exposiciones en archivos JS
                   Autor: hidalg0d

jsexposures is a Python tool designed to scan JavaScript files for sensitive information exposure. It helps security researchers and bug bounty hunters identify potential leaks of API keys, tokens, passwords, and other sensitive data in JavaScript endpoints.

## Features

- **Multi-Pattern Matching**: Utilizes regular expressions to detect a wide range of sensitive information.
- **Concurrent Requests**: Processes multiple URLs simultaneously to speed up scanning.
- **Results Logging**: Saves findings to a text file for easy review.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/jsexposures.git
   cd jsexposures 

1.  Install required packages:

    `pip install requests`

Usage
-----

1.  Prepare a text file named `js_endpoints.txt` with URLs of JavaScript files to scan, one URL per line.

2.  Run the tool:

    `python jsexposures.py`

3.  Check the `resultados_exposiciones.txt` file for any sensitive information found.

Contributing
------------

Contributions are welcome! If you have suggestions or improvements, feel free to create a pull request or open an issue.

License
-------

This project is licensed under the MIT License. See the <LICENSE> file for details.

Author
------

This tool was developed by **hidalg0d**.


 `Feel free to modify any sections or add additional information as needed!`
