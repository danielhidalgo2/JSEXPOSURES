JSEXPOSURES
===========

![image](https://github.com/user-attachments/assets/f98c981c-13bf-4e04-a77e-fc6801506559)

**jsexposures** is a Python tool designed to scan JavaScript files for sensitive information exposure. It helps security researchers and bug bounty hunters identify potential leaks of API keys, tokens, passwords, sensitive comments, and other confidential data in JavaScript endpoints.

✨ Features
----------

-   **Multi-Pattern Matching**: Utilizes an extensive set of regular expressions to detect a wide range of sensitive information, such as API keys, credentials, and JWT tokens.
-   **Sensitive Comment Detection**: Identifies comments that may indicate potential security issues or hidden sensitive information (`TODO`, `FIXME`, `password`, `secret`, etc.).
-   **Concurrent Requests**: Processes multiple URLs simultaneously to maximize efficiency and speed.
-   **Graceful Exit**: Handles `Ctrl+C` interruptions gracefully, ensuring that the program exits cleanly without losing results.
-   **Results Logging**: Saves findings in both JSON and text formats for easy review and analysis.
-   **Customizable Logging Levels**: Allows users to define the level of log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).

📦 Installation
---------------

1.  Clone the repository:

    `git clone https://github.com/danielhidalgo2/jsexposures.git
    cd jsexposures`

2.  Install the dependencies:


    `pip install -r requirements.txt`

📝 Usage
--------

1.  **Prepare a text file** named `js_endpoints.txt` with URLs of JavaScript files to scan, one URL per line.

2.  Run the tool with basic options:


    `python jsexposures.py --file js_endpoints.txt --max-workers 15 --log-level DEBUG`

3.  **Check the output files** for results:

    -   `exposure_results.txt`: Text file with a summary of found exposures.
    -   `exposure_results.json`: JSON file with detailed information about each exposure.

### ⚙️ Command-Line Options


```
usage: jsexposures.py [-h] [--file FILE] [--max-workers MAX_WORKERS] [--log-level LOG_LEVEL]

JS Exposures Finder - A tool to scan JavaScript files for sensitive information.

optional arguments:
  -h, --help            show this help message and exit
  --file FILE           Path to the file containing JS URLs to scan (default: js_endpoints.txt)
  --max-workers MAX_WORKERS
                        Number of concurrent threads to use for scanning (default: 10)
  --log-level LOG_LEVEL Set the logging level (default: INFO). Available levels: DEBUG, INFO, WARNING, ERROR.
```

### 📜 Example Commands

1.  **Basic Scan** with default options:

    `python jsexposures.py --file js_endpoints.txt`

2.  **Detailed Scan** with 15 concurrent threads and more verbose output:

    `python jsexposures.py --file js_endpoints.txt --max-workers 15 --log-level DEBUG`

3.  **Use a Custom File** and reduce concurrent threads:

    `python jsexposures.py --file custom_endpoints.txt --max-workers 5 --log-level INFO`

📂 Output Formats
-----------------

The tool provides results in two formats for easier analysis:

-   **TXT Output (`exposure_results.txt`)**: Contains a summary of each match with the format:

    `Found an exposure: "YOUR_API_KEY_12345" (API Key) at URL "https://example.com/script.js" | Length: 16`

-   **JSON Output (`exposure_results.json`)**: Provides detailed information structured in the following format:

    `[
        {
            "url": "https://example.com/script.js",
            "match": "YOUR_API_KEY_12345",
            "description": "API Key",
            "length": 16
        },
        ...
    ]`

📌 Key Patterns Detected
------------------------

-   **API Keys & Secrets**:

    -   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GOOGLE_API_KEY`, etc.
-   **Sensitive Comments**:

    -   `// TODO: Update credentials`
    -   `/* FIXME: Hardcoded password here */`
    -   `# Debug note: Remember to change the key`
-   **Credentials**:

    -   Passwords, tokens, authorization headers, and more.

🤝 Contributing
---------------

Contributions are welcome! If you have suggestions or improvements, feel free to create a pull request or open an issue. Here are a few ways to contribute:

-   Propose additional patterns for detecting more secrets.
-   Improve the existing code structure or add new features.
-   Report bugs or suggest improvements in the issue tracker.

🧑‍💻 Author
------------
This tool was developed and maintained by **hidalg0d**. Feel free to reach out for questions, suggestions, or feedback.
