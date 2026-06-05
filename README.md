# Site Monitoring Dashboard

Локальный веб-дашборд для мониторинга доступности сайтов, HTTP-статусов, SSL-сертификатов и вручную заданных дат окончания хостинга или домена.

## Запуск

```powershell
python app.py
```

Откройте `http://127.0.0.1:8000`.

Начальный вход:

- логин: `admin`
- пароль: `qwerty455`

Пароль хранится в виде `scrypt`-хеша. В интерфейсе есть смена пароля, а данные и сессии хранятся в SQLite-файле `monitor.db`.

## Настройки

Через переменные окружения можно изменить:

- `DASHBOARD_HOST` и `DASHBOARD_PORT`
- `DASHBOARD_DB`
- `CHECK_INTERVAL_SECONDS`
- `SESSION_TTL_HOURS`
- `HTTP_TIMEOUT_SECONDS`
- `SSL_TIMEOUT_SECONDS`
- `CHECK_WORKERS`
