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
