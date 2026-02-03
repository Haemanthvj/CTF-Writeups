1) PascalCTF - Web Challenge (Travel)

   Challenge Overview

    The "Travel" web challenge on PascalCTF involved a web application that displayed information based on a user-provided index. The goal was to exploit a vulnerability in the backend to retrieve the flag stored in a local file.

   Vulnerability: Local File Inclusion (LFI) via Path Traversal

    The vulnerability was found in the /api/get_json endpoint. This endpoint accepted a JSON payload with an index key. The application used this input to construct a file path on the server to retrieve and display data.

    Because the application did not properly sanitize the index input, an attacker could use path traversal sequences (e.g., ../) to access files outside the intended directory

   Exploitation Steps
     1. Initial Analysis
         The web interface allowed users to select a page number (1 through 7). Each selection sent a POST request to /api/get_json with a JSON body containing the selected index.
     2. Identifying the Vulnerability
         By testing different inputs for the index parameter, it was determined that the server was vulnerable to path traversal. The challenge description or hints indicated that the flag was located at /app/flag.txt.
     3. Executing the Attack
         To retrieve the flag, a POST request was sent to the vulnerable endpoint using curl. The payload utilized ../ to navigate up from the default data directory to the parent directory where flag.txt was located.

   Command:

   curl -X POST "https://travel.ctf.pascalctf.it/api/get_json" \
     -H "Content-Type: application/json" \
     -d '{"index": "../flag.txt"}'

   Flag:
      The server responded with the flag: pascalCTF{4ll_1_d0_1s_tr4v3ll1nG_4r0und_th3_w0rld}


2)  JSHit (PascalCTF 2026)
     1. Initial Reconnaissance
       Upon navigating to the challenge URL, the page appears nearly empty with a dark background and a message hinting at the author's frustration with JavaScript.

      Checking the Page Source (Ctrl+U) reveals a simple HTML structure:
      div with id="page".
      A large block of esoteric symbols inside a <script id="code"> tag.
      The script consists entirely of six characters: [ ] ( ) ! +. This confirms the use of JSFuck, an esoteric and educational programming style where standard       JavaScript is rewritten into highly obfuscated, yet functional code.
      
      2. Technical Analysis
          JSFuck works by utilizing JavaScript's type conversion rules. For example:
         +[] evaluates to 0.
         +!![] evaluates to 1.
         (![]+[])[+[]] evaluates to the character "f" (the first letter of "false").
          By combining these building blocks, the author can construct strings like "eval" or "constructor" and execute arbitrary logic. In this challenge, the            script was designed to generate the flag and inject it into the page div, while simultaneously deleting itself from the DOM to prevent easy inspection.
      
      3. Exploitation & De-obfuscation

         The most effective way to decode JSFuck in a CTF is via the browser's console, which acts as a native de-obfuscator.
         The "Null" Obstacle

         Initial attempts to grab the script content using document.getElementById('code') failed with a TypeError: null. This confirmed that the script tag was          "self-destructing" (removing itself from the DOM) immediately after execution to hide its tracks.
         The Solution: Intercepting Execution
         To reveal the hidden content, we needed to evaluate the JSFuck block as a string expression rather than an executable function.

         Capture: We copied the raw JSFuck symbols from the source code.

          Modification: JSFuck blocks typically end with () to execute the generated function. By removing these final parentheses, the engine returns the function body as a string instead of running it.

    Command: In the browser console, we defined a variable to hold the symbols:
    JavaScript

    let myCode = [PASTED_SYMBOLS_WITHOUT_TRAILING_PARENS];
    console.log(myCode.toString());

4. Capture the Flag
    Executing the modified block revealed the underlying logic: document.getElementById('page').innerHTML = "pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}".

Flag: pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}
