# Web Security Audit Toolkit

A collection of automated Python scripts designed to perform a security audit on a website. This toolkit helps identify common vulnerabilities and misconfigurations in a simple, straightforward way.

---

## Getting Started

Follow these steps to get the toolkit up and running on your local machine.

### Prerequisites

*   You must have Python 3 installed on your system.

### Installation

1.  **Get the code:**
    Clone or download the project files to a folder on your computer.

2.  **Install required packages:**
    All necessary Python libraries are listed in `requirements.txt`. Open your terminal in the project folder and run:
    ```sh
    pip install -r requirements.txt
    ```

---

## How to Use

The main script to run all tests is `main.py`. You provide it with a target URL and can specify the intensity of the audit.

### Running an Audit

You can choose from three audit levels. If you don't specify a level, it will run a `basic` audit by default.

*   **Basic Audit (Recommended for a quick check):**
    ```sh
    python3 main.py http://example.com
    ```
    or
    ```sh
    python3 main.py --level basic http://example.com
    ```

*   **Advanced Audit (More detailed):**
    ```sh
    python3 main.py --level advanced http://example.com
    ```

*   **Extreme Audit (Intrusive - use with caution):**
    ```sh
    python3 main.py --level extreme http://example.com
    ```

### Running Specific Tests

If you only want to run one or more specific tests, use the `--tests` flag followed by the test names.

```sh
python3 main.py --tests tech headers http://example.com
```

---

## Audit Levels Explained

*   ### Basic Audit (`--level basic`)
    This is a quick and safe check. It looks at your website's public information and basic security settings without trying to break anything. It's like checking if your doors and windows are closed.

*   ### Advanced Audit (`--level advanced`)
    This audit is more thorough and includes all `basic` checks. It actively looks for hidden pages and checks for more complex security settings. It's like checking the locks and looking for less obvious entry points.

*   ### Extreme Audit (`--level extreme`)
    This is the most intense audit and includes all `advanced` checks. It actively tries to find vulnerabilities by sending test payloads to your website.
    **Warning:** This is an intrusive scan and should **only** be run on websites you have explicit permission to test.

---

## Available Scripts

Here is a list of the currently available test scripts:

| Test Name      | Audit Level | Description                                          |
|----------------|-------------|------------------------------------------------------|
| `tech`         | Basic       | Identifies website technologies (e.g., WordPress).   |
| `headers`      | Basic       | Checks for important security headers.               |
| `clickjacking` | Basic       | Tests if the site is vulnerable to clickjacking.     |
| `links`        | Basic       | Finds broken links on the homepage.                  |
| `subdomain`    | Advanced    | Tries to find common subdomains.                     |
| `xss`          | Extreme     | Runs a basic test for Cross-Site Scripting (XSS).    |

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
