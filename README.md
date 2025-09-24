# xss-detector
Advanced Go XSS Scanner is a powerful, multi-threaded XSS scanning tool written in Go. It automatically detects input parameters in web pages, tests for reflected XSS via query parameters and URL paths, and logs results to a file. Designed for ethical hacking labs and penetration testing exercises.


Features

✅ Multi-threaded scanning for speed

✅ Automatic detection of HTML input parameters

✅ Query parameter XSS testing

✅ Path-based XSS testing (e.g., /search/<payload>)

✅ Multiple advanced XSS payloads (script, SVG, event handlers, media tags, etc.)

✅ Logs results to xss_results_full.txt

✅ Easy to use in labs (local or test environments)

⚠️ Safety Warning

This tool is intended for educational and lab use only. Never scan websites without explicit permission. Using it against public websites or without authorization is illegal.



Installation

# Clone this repository
git clone https://github.com/YourUsername/advanced-go-xss-scanner.git
cd advanced-go-xss-scanner

# Install dependencies
go mod tidy

# Run the scanner
go run main.go



Usage

# Open main.go and set your target URL
target := "https://localhost:8080/search/" # lab URL

# Run the scanner
go run main.go
