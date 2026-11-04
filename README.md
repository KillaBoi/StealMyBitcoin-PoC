<p align="center">
  <sub>sponsored with ❤️ by</sub>&nbsp;<a href="https://hextree.io" title="he didnt want a dono so i gave him this banner, ty mr liveoverflow for helping"><img src="https://i.ibb.co/fVZ3Nvcx/hextree.jpg" alt="hextree.io" height="22" align="middle"></a>
</p>

# Steal My Bitcoin CTF proof of concept

> One live PHP callback against the Steal My Bitcoin challenge, start to finish, in a single standard-library Python file.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)
![Target](https://img.shields.io/badge/target-PHP%208.4.26%20Alpine-777bb4)
![Lab](https://img.shields.io/badge/lab-docker-2496ed)

This README explains [stealmybitcoin_poc.py](stealmybitcoin_poc.py), a single-file Python reproduction of the request sequence used in my Steal My Bitcoin CTF run. It uses only Python's standard library. The script builds the requests itself, checks each leak before moving on, and records the HTTP bytes from a new run.

This can probably be done easier without all the extra debug crap and as in my John Hammond video about the Steam Local Privilege Escalation I discovered, you could probably clean up this ugly PoC.

> [!NOTE]
> ⚠️ **Honestly please clean it up or make your own better version that isn't crumpled by Sol.** ⚠️

**Everything below is written against the Docker lab**, not the live challenge. The lab is a local Alpine PHP 8.4.26 CLI server behind nginx, which is the same build and worker model the offsets were calibrated on. [Stand it up in a minute](#the-lab) and the whole chain runs end to end on your own machine. The live run that actually solved the challenge is kept as a historical note at the [bottom](#the-live-run-that-solved-it).

```
  stage                 what goes out                        what comes back
  ─────────────────────────────────────────────────────────────────────────────
  0  health      GET /php-version.php                 ->  PHP 8.4.26 confirmed
  1  heap leak   249,042 B producer + 8 x   6,672 B   ->  256 B cookie
                 (OOM poisons a worker)                   └─ Zend chunk base
  2  code leak   251,557 B producer + 8 x  92,388 B   ->   16 B cookie
                 (OOM poisons a worker)                   └─ zval_ptr_dtor
  3  callback    368,812 B POST                       ->  forged HashTable runs
                 (fake HashTable + command)               └─ zif_system(cmd)
  ─────────────────────────────────────────────────────────────────────────────
  20 HTTP requests at most. No looping, no retries.
```

## The short version

1. A small multipart upload makes PHP chew through far more memory than the wire size suggests.
2. When it runs out of memory partway through session upload-progress parsing, PHP leaves stale state behind in a worker that then gets reused.
3. Shape the follow-up requests right and bytes fall out through session cookies. I read those as a heap address and a PHP code address.
4. With both addresses, a final request drops a forged PHP structure where cleanup will find it, and cleanup calls `zif_system`, PHP's handler for `system`.
5. That command sends back a fresh proof marker and one `print-flag` result over the connection that is still open.

> **Why two addresses?** The OS randomizes where PHP's code and heap land, independently. The heap leak tells the script where to put the forged structure, the code leak tells it where the function it wants to call actually lives. Addresses from an earlier worker or an earlier run are not safe substitutes, and every time I tried it the attempt just failed.

## Contents

- [The lab](#the-lab)
- [Start here](#start-here)
- [What each request does](#what-each-request-does)
  - [1. How a small producer reaches the memory limit](#1-how-a-small-producer-reaches-the-memory-limit)
  - [2. How the heap address is recovered](#2-how-the-heap-address-is-recovered)
  - [3. How the PHP code address is recovered](#3-how-the-php-code-address-is-recovered)
  - [4. How the final request reaches `system`](#4-how-the-final-request-reaches-system)
- [Reading the result](#reading-the-result)
- [How often it actually works](#how-often-it-actually-works)
- [The live run that solved it](#the-live-run-that-solved-it)
- [Jargon, briefly](#jargon-briefly)
- [Thanks](#thanks)

---

## The lab

The offsets in this PoC are calibrated for **Alpine PHP 8.4.26 running the built-in CLI server with four workers**. The lab reproduces exactly that, behind nginx, on loopback.

> [!IMPORTANT]
> The build matters more than the version string. A Debian `php:8.4.26-fpm` stack reports the same `PHP/8.4.26` but has a different binary layout, so the code-pointer fingerprint will never match and the run aborts at the code-leak stage. Use the Alpine image below.

Three small files. Put them in an empty directory:

**`public/php-version.php`** (the health endpoint, and the only page the PoC needs)

```php
<?php
header('Content-Type: text/plain');
echo 'PHP ', PHP_VERSION, "\n";
echo 'PID: ', getmypid(), "\n";
```

**`print-flag`** (stand-in for the challenge binary, must be executable)

```sh
#!/bin/sh
printf '%s\n' 'LOCAL_DUMMY_WIF_NEVER_USE'
```

**`nginx.conf`**

```nginx
events {}
http {
    server {
        listen 80;
        server_name _;
        location / {
            proxy_pass http://ctf-cross-php:8000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
        }
    }
}
```

Then bring it up:

> [!TIP]
> These same files are checked in under [`lab/`](lab/) with a [`docker-compose.yml`](lab/docker-compose.yml). If you have Compose, `cd lab && docker compose up -d` stands the whole thing up on `127.0.0.1:18166`, and `docker compose down` tears it back down. The manual `docker run` recipe below is the equivalent, spelled out.

```bash
docker network create ctf-cross-net

docker run -d --name ctf-cross-php --network ctf-cross-net \
  --read-only --tmpfs /tmp:rw,size=32m,mode=1777 --memory 1g \
  -v "$PWD/public:/app:ro" \
  -v "$PWD/print-flag:/usr/local/bin/print-flag:ro" \
  -e PHP_CLI_SERVER_WORKERS=4 \
  php:8.4.26-fpm-alpine3.23 php -S 0.0.0.0:8000 -t /app

docker run -d --name ctf-cross-nginx --network ctf-cross-net \
  -p 127.0.0.1:18166:80 \
  -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
  nginx:1.27-alpine
```

Check it:

```console
$ curl -s http://127.0.0.1:18166/php-version.php
PHP 8.4.26
PID: 1
```

The PID varies with whichever worker answers, and that is fine. The version line is the part the PoC checks.

Tear it down with `docker rm -f ctf-cross-nginx ctf-cross-php && docker network rm ctf-cross-net`.

> [!TIP]
> On Windows, run those `docker run` commands from PowerShell, or replace `$PWD` with a full drive path like `C:/lab`. In Git Bash `$PWD` expands to an MSYS path such as `/tmp/...`, which Docker Desktop resolves inside its own VM. The bind mounts then silently create empty directories where `nginx.conf` and `print-flag` should be, and the containers come up broken.

A couple of notes on that recipe. The image is the `fpm` tag but the container runs `php -S`, so the SAPI is `cli-server`, which is what the calibration was measured against. `PHP_CLI_SERVER_WORKERS=4` is what gives the leak stages more than one worker to race for. My own lab harness also passed `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` so it could attach a tracer to the workers; the PoC itself never does that, so those are left out above.

---

## Start here

Python 3.11 or newer, standard library only, nothing to install:

```powershell
python .\stealmybitcoin_poc.py --url http://127.0.0.1:18166/php-version.php
```

Run it with no arguments and it prints its help and exits without touching the network.

A good run looks like this:

```console
[health] PHP 8.4.26 confirmed
[heap] strict Zend base 0x78113e800000
[code] strict zval_ptr_dtor 0x615b1f512930
{"stage": "final", "nonce": "1ef0e73d8615157a", "execution_proof_verified": true, "response_path": "..."}
```

Note the low 21 bits of that `zval_ptr_dtor` value: `0x112930`, exactly the fingerprint the script expects from this Alpine build. That is the check that rejects a mismatched image.

The response body that comes back:

```
<br />
<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 131072 bytes) in <b>Unknown</b> on line <b>0</b><br />
1ef0e73d8615157a
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
0ec066e8b91457c7c19b5612f3e2ded7f117df08f402693669c1ffc2cfc24942  /usr/local/bin/print-flag
LOCAL_DUMMY_WIF_NEVER_USE
```

The PHP fatal, then the nonce this run generated, then `id`, then the hash of the binary it resolved, then the dummy flag. Exit status is `0` on a verified run and `1` on anything else.

> [!WARNING]
> The producer deliberately walks PHP into its memory limit. Only run this somewhere that behaviour is authorized. The script will only talk to the challenge endpoint or a loopback lab URL, and anything else aborts before a packet goes out.

One run means one health GET, up to two leak batches, and at most one final request. No looping, no retries. Every multipart body stays under 1 MiB, though each leak batch pipelines nine separate requests down one connection.

| Flag | What it does |
| --- | --- |
| `--url` | Lab endpoint, or the challenge. Required to do anything. |
| `--output-dir` | Where to write the run's evidence. Defaults to `poc-run-<UTC timestamp>`. |

---

## What each request does

| Step | What goes out, what should come back | Why |
| --- | --- | --- |
| Health | One ordinary `GET /php-version.php` must return HTTP 200, `PHP 8.4.26`, and `X-Powered-By: PHP/8.4.26`. | Keeps the memory-limit payload away from a changed or unhealthy endpoint. |
| Heap leak | One 249,042-byte multipart producer, then eight pipelined 6,672-byte consumers. The producer must return a PHP 128 MiB memory-limit fatal. A consumer may return a 256-byte `PHPSESSID` cookie. | Four or more pointer-looking values in that cookie have to agree on one aligned 2 MiB Zend heap base. |
| Code leak | One 251,557-byte producer, then eight pipelined 92,388-byte consumers. A consumer may return a 16-byte `PHPSESSID` cookie. | Its first eight bytes must encode `16`, and its second eight must look like the locally calibrated `zval_ptr_dtor` pointer. |
| Final callback | One 368,812-byte multipart POST. | A forged PHP `HashTable` points cleanup at `zif_system` and supplies a command argument. The fresh nonce, `id` output, and `print-flag` binary hash are the evidence that the callback actually ran. |

That is **20 HTTP requests at most**: one health check, nine per leak batch, one final request. All eight consumers in a batch go out before the first response is read, which helps the timing, but it also means you cannot pull them back if the producer fails. A failed or malformed batch stops the next stage.

### 1. How a small producer reaches the memory limit

The producer is `multipart/form-data` carrying `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` fields. PHP handles upload progress while it is still parsing the request. Hundreds of empty file controls get names like `f[0][x][x]...` with dozens of nested `[x]` segments, so the body stays around 250 KiB on the wire while parsing it spawns piles of nested PHP arrays and all the allocations that come with them. The producer also carries 1,001 distinct empty cookie names, which is what the request builder was configured to send at the time.

The fatal you want says PHP exhausted its 128 MiB memory limit. What you are actually after is the stale state this particular failure leaves behind in a worker.

> [!IMPORTANT]
> On its own, a memory-limit fatal or an nginx 502 proves nothing about an address leak or code execution.

### 2. How the heap address is recovered

The next request goes after the memory tied to that stale session state. It repeats a single numeric form key, then slips in a crafted value that changes the length PHP uses when it writes `PHPSESSID`. Land on the right reused worker with the right heap layout and the cookie comes back 256 bytes instead of the usual 32, with neighbouring heap data sitting inside it.

`heap_candidate()` walks that cookie as little-endian 64-bit words, and will only accept a base if at least four pointer-looking values fall in the same aligned 2 MiB heap region. On top of that the runner wants HTTP 200, the expected PHP version, valid cookie lengths from all eight consumers, and exactly one agreed base. Anything short of that and it stops.

### 3. How the PHP code address is recovered

A second producer triggers the same memory-limit condition. Its consumer uses a different array layout, calibrated locally to shake out a PHP function pointer. The cookie you want is exactly 16 bytes: an eight-byte value of `16`, then a pointer read as `zval_ptr_dtor` against the Alpine PHP fingerprint.

The script checks the pointer's range and its low 21 bits, `0x112930`. That is the page offset of the symbol in the Alpine PHP 8.4.26 image, and ASLR does not move it. Treat it as a fingerprint, not as proof the remote executable is byte for byte the same thing. For this layout, `zif_system` works out as:

```text
zif_system = zval_ptr_dtor - 0x204BC0
```

Both leaks have to come from the current invocation. The script will not load historical pointer values into a live attempt.

### 4. How the final request reaches `system`

The final POST parks a 384-byte forged `HashTable` in a multipart field I control. That structure overlaps a fake call frame and a fake `zend_string` holding the command. A 276-byte primer supplies a pointer into the controlled region, then a long form-field name drives another memory-limit failure. In the cleanup path, PHP reads the forged table's `pDestructor` as `zif_system` and hands it the string argument.

```text
         0x00  ┌──────────────────────────┐
               │ zend_array header        │  pDestructor -> zif_system
         0x20  ├──────────────────────────┤
               │ bucket / fake call frame │  arg1 -> zend_string below
         0x80  ├──────────────────────────┤
               │ zend_string header       │
         0x98  ├──────────────────────────┤
               │ command (231 B max)      │
         0x180 └──────────────────────────┘
```

The target address uses a distance measured in the four-worker Alpine setup:

```text
fake_table = zend_heap_base - 0x8400000 + 0x16D1D8
```

That distance depends on the worker and the allocation layout. Change the image, the memory configuration, or the worker count and this falls over even though the PHP version still reads 8.4.26.

The command that originally worked just ran `print-flag` once. This version prints a fresh random nonce, the output of `id` (UID and GID), and the SHA-256 of the resolved `print-flag` binary before invoking `print-flag` once. It hunts down the active accepted socket under `/proc/self/fd` so the output actually reaches the HTTP response. Ordinary process stdout got me nothing.

---

## Reading the result

Every run drops a new `poc-run-<UTC timestamp>` directory, unless `--output-dir` points at a new one. Everything is written before it is validated, so a run that aborts halfway still leaves usable evidence. The files worth opening:

| File | Contents |
| --- | --- |
| `heap.request.http`, `code.request.http` | The plaintext HTTP bytes handed to each leak-stage socket's `sendall`, one producer plus eight pipelined consumers. If the transport fails you cannot be sure what actually got delivered. |
| `heap.response.http`, `code.response.http` | Plaintext HTTP bytes read back off each leak-stage socket, cookies included. |
| `heap.json`, `code.json` | Parsed response status, lengths, hashes, and candidate addresses. |
| `final.request.http` | The final request as constructed, headers and multipart body. Same caveat about transport failures. |
| `final.response.http`, `final.response.body`, `final.response.headers.json` | The final response as read, plus its parsed body and headers. Against the live challenge this body may contain a private WIF. |
| `final.json`, `run.json` | Summary fields, and whether the expected execution markers showed up. |

`execution_proof_verified: true` means the final response came back HTTP 200 carrying the fresh nonce, an `id` result, and a SHA-256 line for `print-flag`.

> [!CAUTION]
> Against the real challenge a run directory can contain a live private key. Publish this source file, not a run's output.

The script makes no claim about whether a returned WIF controls the advertised Bitcoin address. A checksum-valid WIF only tells you the string encodes a private key properly. Deriving the address and comparing it is a separate job.

---

## How often it actually works

Both leak stages are races against three other workers, so a single run is not expected to succeed every time. Ten consecutive runs against the lab described above, with no retries and nothing else talking to the container:

| Result | Count |
| --- | --- |
| `execution_proof_verified: true` | 7 |
| Reached the callback, markers absent | 2 |
| Heap leak never landed | 1 |

So roughly seven runs in ten. Worth knowing that both leaks are stable once a container is up: every run against the same container returned the same `zend_heap_base` and the same `zval_ptr_dtor`, because the workers persist and ASLR is per process, not per request. What varies between runs is purely which worker answers which pipelined consumer.

The two failures are worth recognising, because they look nothing alike:

**Heap stage misses.** The producer OOMs correctly and all eight consumers come back HTTP 200 with ordinary 32-byte cookies. No leak, no candidate, so the run stops before anything is forged:

```
[abort] RuntimeError: heap: expected one strict address, found 0
```

**Callback misses.** Both leaks succeed, the final POST returns HTTP 200, and the body is only the memory-limit fatal with none of the three markers. The forged table did not land where cleanup read it:

```json
{"status": 200, "nonce_seen": false, "id_seen": false,
 "binary_hash_seen": false, "execution_proof_verified": false}
```

Neither case is a partial success, and neither is retried automatically. Just run it again.

---

## The live run that solved it

At **15:47:38 UTC on 25 October 2026** the earlier guarded runner logged a healthy PHP 8.4.26 page, a heap stage with an HTTP 200 memory-limit fatal and a 256-byte cookie, and a code stage with an HTTP 200 memory-limit fatal and a 16-byte cookie. Its final 368,812-byte POST came back HTTP 200 with a 204-byte body: the PHP fatal, then one checksum-valid WIF. A local nginx/PHP lab reproduced the callback and the socket-output method with dummy data. Put together, that is a strong case for live command execution inside the PHP process.

**Worth being straight about the gaps.** The original run never captured its full outgoing HTTP request or the response headers. The complete request was reconstructed afterwards from the builders and whatever metadata was left over, and a matching hash would not promote that into an original wire capture. I never pulled the remote PHP ELF or the `print-flag` binary, they were simply executed, as noted on the challenge website. The one WIF I recovered did not derive the prize address shown on the saved homepage at the time. That was a mistake on the creator's side, and it was acknowledged over email.

---

## Jargon, briefly

| Term | Meaning |
| --- | --- |
| **Zend heap** | PHP's memory area for request values and internal structures. |
| **Worker** | One PHP process handling requests. The stale state and the later consumer need the same reused process, and pipelining does not guarantee you get it. |
| **`PHPSESSID` cookie** | Where the unintended memory bytes turn up during the leak stages. |
| **`zval_ptr_dtor`** | A PHP internal function pointer, used here to anchor the code-image address calculation. |
| **`zif_system`** | PHP's internal handler for `system`, used as the forged cleanup callback. |
| **WIF** | Wallet Import Format, an encoding of a Bitcoin private key. A valid checksum says nothing about who owns a particular wallet address. |

### Reading the code instead

It is laid out in attack order and the section banners match the four stages above:

```
leak_producer()  ->  heap_consumer()  ->  code_consumer()
                 ->  run_leak_stage()
                 ->  fake_hashtable()  ->  final_multipart()  ->  final_request()
```

Every tuned number lives in the calibration block at the top or in the `STAGES` table, so that is the place to look when something needs re-measuring against a different build.

---

## Thanks

- [cloudlandsdev](https://news.ycombinator.com/item?id=50224916) for the challenge!
- [LiveOverflow](https://www.youtube.com/liveoverflow) who makes amazing videos and was very helpful when I needed to contact the creator :)
- I'm still waiting for my Overwatch session lusilly :|
