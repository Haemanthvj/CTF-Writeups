# CTF Writeup: Silent Whisper
**Category:** Steganography  
**Points:** 200  
**Author:** hx  
**Flag:** `Zer0D4yH31st{finally_y8u_f1nd_1t}`

---

## Challenge Description

> "Some secrets don't live in pixels."  
> A forgotten image. A hidden trail. A final vault.

**Given file:** `output.jpeg` (a blurry parrot image)

---

## Solution

This was a 3-layer steganography challenge. Each layer feeds into the next.

---

### Layer 1 — JPEG Comment Field (Base64 → URL)

The hint *"Some secrets don't live in pixels"* is the key clue — the secret is in the **metadata**, not the image data itself.

```bash
exiftool output.jpeg
```

This reveals a **JPEG comment field** containing a base64-encoded string:

```
aHR0cHM6Ly9pLmliYi5jby9IVFFIUWJ6cC9TY3JlZW5zaG90LWZyb20tMjAyNi0wNi0wNS0yMS0wOC0yNS5wbmc=
```

Decode it:

```bash
exiftool -Comment -b output.jpeg | base64 -d
```

**Output:**
```
https://i.ibb.co/HTQHQbzp/Screenshot-from-2026-06-05-21-08-25.png
```

Download the image at that URL:

```bash
curl -L "$(exiftool -Comment -b output.jpeg | base64 -d)" -o steg.png
```

---

### Layer 2 — Birds on a Wire Cipher (steg.png → Password)

`steg.png` contains a small image of **3 birds sitting on a wire**.

This is the classic **"Birds on a Wire" cipher** — each bird's size/height encodes a letter.

Upload `steg.png` to **[dcode.fr/birds-on-wire-cipher](https://www.dcode.fr/birds-on-wire-cipher)** and decode:

```
Bird 1: TALL  →  Z
Bird 2: TALL  →  Z
Bird 3: SHORT →  A
```

**Decoded password: `ZZA`**

**Reference — dCode Birds on a Wire result:**

![Birds on a Wire dCode](birds_on_wire_dcode.png)

---

### Layer 3 — Steghide Extraction (output.jpeg → Flag)

Use the decoded password `ZZA` with steghide on the **original** `output.jpeg`:

```bash
steghide extract -sf output.jpeg -p "zza"
```

**Output:**
```
wrote extracted data to "flag.txt"
```

```bash
cat flag.txt
```

```
Zer0D4yH31st{finally_y8u_f1nd_1t}
```

**Reference — steghide extraction terminal output:**

![Steghide flag extraction](steghide_flag_extract.png)

---

---

# CTF Writeup: One Day...
**Category:** Steganography  
**Points:** 150  
**Author:** loopXvedant  
**Flag:** `0dayheist{1_dAy_U_will_Be}`

---

## Challenge Description

> "Two souls, one sunset, and a memory frozen in time. But some memories are never truly forgotten."  
> "Maybe this picture is trying to say something... :)"

**Flag Format:** `0dayheist{}`  
**Given file:** `Beach.jpg`

---

## Solution

The description hints that the image is "trying to say something" — pointing directly at **metadata**.

Run exiftool on the file:

```bash
exiftool Beach.jpg
```

The **Comment** field in the EXIF metadata contains the flag directly:

```
Comment : 0dayheist{1_dAy_U_will_Be}
```

**Flag:** `0dayheist{1_dAy_U_will_Be}`

---

---

# CTF Writeup: Bella Ciao
**Category:** Reverse Engineering  
**Flag:** `0Day-Heist{bella_ciao_never_dies}`

---

## Challenge Description

Given file: `bella_ciao.exe`

---

## Solution

### Step 1 — File Identification

```bash
file bella_ciao.exe
```

Confirmed it's a **Windows 64-bit PE executable**.

---

### Step 2 — Static Analysis with strings

```bash
strings -a bella_ciao.exe
```

Found:
```
Now Playing: %s
Bella Ciao
```

No flag visible, so moved to disassembly.

---

### Step 3 — Disassembly with objdump

```bash
objdump -d -M intel bella_ciao.exe | less
```

Inside `main`, just before the `printf`, suspicious bytes are loaded onto the stack but never used by the program:

```asm
movabs rax, 0x031f1277534b1e6a
movabs rdx, 0x46464f4841051619
movabs rax, 0x4f45054b0349354b
movabs rdx, 0x594f034e35584f5c
mov WORD PTR [rbp-0x10], 0x0747
```

---

### Step 4 — Extract the Hidden Bytes

Since the binary is **little-endian**, reverse the byte order of each value:

```
6a 1e 4b 53 77 12 1f 03
19 16 05 41 48 4f 46 46
4b 35 49 03 4b 05 45 4f
5c 4f 58 35 4e 03 4f 59
47 07
```

---

### Step 5 — XOR Decode

Trying XOR with `0x2a` reveals the hidden message:

```python
data = bytes.fromhex(
    "6a1e4b5377121f0319160541484f46464b3549034b05454f5c4f58354e034f594707"
)
print(bytes([b ^ 0x2a for b in data]))
```

Output leaks the key words:
```
bella  ciao  never  dies
```

---

### Flag

```
0Day-Heist{bella_ciao_never_dies}
```

---

---

# CTF Writeup: Sierra's Evidence
**Category:** Forensics  
**Points:** 300  
**Flag:** `0Day-Heist{metadata_tells_all}`

---

## Challenge Description

Given file: `evidences.png`

The challenge hinted the image looked harmless, but important evidence was hidden inside.

---

## Solution

### Step 1 — File Identification & Metadata Check

```bash
file evidences.png
exiftool evidences.png
pngcheck -v evidences.png
```

Results:
- Valid PNG: `1325 x 768, 8-bit/color RGBA, non-interlaced`
- `exiftool` showed no useful metadata
- `pngcheck` showed only standard chunks: `IHDR`, `IDAT`, `IEND` — no `tEXt`, `zTXt`, or `iTXt` chunks

---

### Step 2 — LSB Analysis with zsteg

PNG forensics challenges often hide data in pixel bit planes, so:

```bash
zsteg evidences.png
```

This revealed a hidden string in the **red channel LSB**:

```
b1,r,lsb,xy .. text: "ODay-Heist{metadata_tells_all}"
```

---

### Step 3 — Manual Extraction to Confirm

```bash
zsteg -E b1,r,lsb,xy evidences.png | head -c 80
```

Output:
```
ODay-Heist{metadata_tells_all}
```

The first character appears as uppercase `O` due to bit rendering, but the flag format specifies digit `0`. The correct flag is:

---

### Flag

```
0Day-Heist{metadata_tells_all}
```

---

---

# CTF Writeup: Security Camera #14
**Category:** Forensics  
**Flag:** `0Day-Heist{caught_on_camera}`

---

## Challenge Description

Given file: `camera14.png`

Someone had hidden a message inside the image.

---

## Solution

### Step 1 — File Identification & Metadata Check

```bash
file camera14.png
exiftool camera14.png
```

The metadata revealed a suspicious comment:

```
ODay-Heist{There_is_a_big_misunderstanding_sir}
```

But exiftool also warned:

```
Warning: [minor] Trailer data after PNG IEND chunk
```

PNG files must end at the `IEND` chunk — anything after it is suspicious and likely hidden data.

---

### Step 2 — Confirm with pngcheck

```bash
pngcheck -vtp camera14.png
```

Output confirmed:

```
chunk IEND at offset ...
additional data after IEND chunk
ERRORS DETECTED in camera14.png
```

---

### Step 3 — Extract Both Strings

```bash
strings -a camera14.png | grep Heist
```

Two strings found:

```
ODay-Heist{There_is_a_big_misunderstanding_sir}   ← decoy in PNG comment
ODay-Heist{caught_on_camera}                       ← hidden after IEND
```

---

### Step 4 — Confirm the Appended Data

```bash
tail -c 29 camera14.png
```

Output:

```
ODay-Heist{caught_on_camera}
```

The first flag in the comment metadata was a **decoy**. The real flag was appended after the `IEND` chunk.

---

### Flag

```
0Day-Heist{caught_on_camera}
```

---

---

# CTF Writeup: The Hidden Library
**Category:** Steganography / OSINT-style Visual Puzzle  
**Flag:** `0dayhiest{the_key_is_human_intuition}`

---

## Challenge Description

Given files: `challenge.png`, `metadata.txt`, `poem.txt`

---

## Solution

### Step 1 — Metadata Inspection

```bash
exiftool challenge.png
```

Revealed useful hints:

```
Author    : 0dayhiest
Challenge : AI-Resistant Steganography
Comment   : The truth lies in patterns unseen
Hint      : Fibonacci guides the way
```

---

### Step 2 — Read the Poem

```
Backward glances reveal the key,
What once was hidden now breaks free.
```

Key clues extracted from the poem:
- *Seventeen steps*
- *Every third holds truth within*
- *Red before blue makes purple shine*
- *Backward glances reveal the key*

---

### Step 3 — Visual Inspection of the Image

Opening `challenge.png` showed a bookshelf scene. Near the lower shelf, very faint hidden text was visible under a translucent purple area.

After cropping and increasing contrast, the text became readable:

```
no171u7n1_n4muh_s1_y3k_3p
```

---

### Step 4 — Reverse It

The poem's line *"Backward glances reveal the key"* tells us to reverse the string:

```
p3_k3y_1s_hum4n_1n7u171on
```

---

### Step 5 — Decode Leetspeak

```
p3       → the
k3y      → key
1s       → is
hum4n    → human
1n7u171on → intuition
```

Decoded:

```
the_key_is_human_intuition
```

---

### Flag

```
0dayhiest{the_key_is_human_intuition}
```

# CTF Writeup: Chronophage
**Category:** Reverse Engineering  
**Flag:** `ZeroDayHeist{the_decoys_are_the_key_and_the_exit_is_the_entry42}`

---

## Challenge Description

Given file: `chronophage` (ELF binary)

> "Every decoy matters. The exit is the entry."

---

## Solution

### Step 1 — File Identification & Initial strings

```bash
file chronophage
strings -a chronophage | grep ZeroDayHeist
```

The binary was a **stripped Rust ELF**. `strings` revealed a huge number of fake flags like `ZeroDayHeist{...}` — all decoys. The hint *"Every decoy matters. The exit is the entry"* confirmed guessing from strings was a dead end.

---

### Step 2 — Running the Binary

```bash
./chronophage
```

The binary asks for a **64-byte recovery flag**.

Wrong format gives:
```
archive rejects the shape
```

Wrong flag with correct format gives:
```
the archive remembers a different future
```

So the first check is only flag shape. Disassembly confirmed the expected format:

```
ZeroDayHeist{ + 50 chars + }
```

Total length: **64 bytes**.

---

### Step 3 — Static Analysis

In the disassembly, the main verification function was found around offset `0xa7e0`. It calls key generator functions, then a large transform function at `0xda00`.

Key constants identified:

```
H1 = 0x09126ec8c581ab37
H2 = 0x850d53f292a8376d
```

The transform repeatedly calls a sub-function at `0xac20`. Using GDB and Unicorn to trace execution, the selector order was recovered:

```
9, 12, 8, 0, 1, 4, 5, 10, 11, 2, 14, 13, 3, 6, 7
```

---

### Step 4 — Symbolic Reversal with Z3

Since each `0xac20` block was individually reversible, the approach was to replay every block **symbolically using Z3**, inverting from the final target state back to the input.

One issue encountered: the final SIMD compare had swapped vector lanes, causing the wrong target initially. After correcting lane order, the proper pre-transform target was:

```
0x7a4d2438bfeabf33
0x079191cc982fc1a32
0x7140f494960e93c6
0x56a8e7c56e826529
0x08094f9ece8c9bb2
0x2166b5b6bb27a3b4
0xa20984c7998eecf5
0xe29f8506de87c317
```

Z3 solved the final inverse with normal flag charset constraints and produced:

```
ZeroDayHeist{the_decoys_are_the_key_and_the_exit_is_the_entry42}
```

---

### Step 5 — Verification

```bash
printf 'ZeroDayHeist{the_decoys_are_the_key_and_the_exit_is_the_entry42}\n' | ./chronophage
```

Output:
```
the exit was the entry
```

---

### Flag

```
ZeroDayHeist{the_decoys_are_the_key_and_the_exit_is_the_entry42}
```
