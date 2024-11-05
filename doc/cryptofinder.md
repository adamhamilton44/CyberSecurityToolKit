# Post Exploitation Tool: Crypto Finder

This guide explains how to use the `crypto_catch` bash script to search for cryptocurrency addresses within a specified file. 

The script supports multiple types of cryptocurrency addresses and scans the provided file for these patterns.

## Usage

### Step 1: Clear the Screen

The script begins by clearing the terminal screen for a clean output display.

### Step 2: Prompt for File Path

You will be prompted to enter the path of the file you want to check for cryptocurrency data:


Provide the path to the file and press Enter.

### Step 3: Define Cryptocurrency Patterns

The script defines regular expressions for various cryptocurrency addresses. The supported cryptocurrencies and their respective patterns are:

- **Bitcoin (BTC)**
  - Patterns: `1[a-zA-HJ-NP-Z1-9]{25,29}`, `3[a-zA-HJ-NP-Z0-9]{25,29}`, `bc1[a-zA-HJ-NP-Z0-9]{25,29}`
- **Ethereum (ETH)**
  - Pattern: `0x[a-fA-F0-9]{40}`
- **Monero (XMR)**
  - Patterns: `4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}`, `8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}`
- **Ripple (XRP)**
  - Pattern: `r[0-9a-zA-Z]{24,34}`
- **Bitcoin Cash (BCH)**
  - Patterns: `1[a-km-zA-HJ-NP-Z1-9]{25,34}`, `3[a-km-zA-HJ-NP-Z1-9]{25,34}`, `q[a-z0-9]{41}`, `p[a-z0-9]{41}`
- **Litecoin (LTC)**
  - Patterns: `L[a-km-zA-HJ-NP-Z1-9]{26,33}`, `M[a-km-zA-HJ-NP-Z1-9]{26,33}`, `3[a-km-zA-HJ-NP-Z1-9]{26,33}`, `ltc1q[a-km-zA-HJ-NP-Z1-9]{26,33}`
- **Dogecoin (DOGE)**
  - Pattern: `D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}`
- **Zcash (ZEC)**
  - Pattern: `t1[a-km-zA-HJ-NP-Z1-9]{33}`
- **Dash (DASH)**
  - Pattern: `X[1-9A-HJ-NP-Za-km-z]{33}`
- **Ronin (RON)**
  - Pattern: `ronin:[a-fA-F0-9]{40}`
- **TRON (TRX)**
  - Pattern: `T[A-Za-z1-9]{33}`
- **Steam Trade URL**
  - Pattern: `http[s]*:\/\/steamcommunity.com\/tradeoffer\/new\/\?partner=([0-9]+)&token=([a-zA-Z0-9]+)`

### Step 4: Process Each Line in the File

The script reads each line from the specified file and checks for matches against the defined cryptocurrency patterns. 

The process is as follows:

1. **Read the File**: The script reads the file line by line.
2. **Skip Empty or Commented Lines**: Lines that are empty or start with a `#` are skipped.
3. **Check for Matches**: For each line, the script checks if it matches any of the cryptocurrency patterns.
   - If a match is found, the type of cryptocurrency and the matching line are displayed: 
     ```
     [Crypto Type] Address found: [Matching Line]
     ```
   - If no match is found, the line is ignored.

### Example

Here's how you might run the script:

1. Run the script.
2. Enter the path to the data file when prompted:
3. View the results for each line in the file.

## Conclusion

This script is a powerful tool for identifying various cryptocurrency addresses within a file. 

By following the prompts and understanding the supported patterns, you can effectively use this script for post-exploitation data analysis.
