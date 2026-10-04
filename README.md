# Конфигурация почтового сервера (Berkut4264)

Снапшот `/etc` почтового сервера (стек: **Postfix + Dovecot + OpenDKIM + OpenDMARC +
Amavis + SpamAssassin**), изначально сохранённый через etckeeper с системы
Ubuntu 19.10.

## Что сделано в ветке `arena/01a10757-berkut4264` (октябрь 2026)

- Проведён аудит сохранившихся конфигов и метаданных etckeeper —
  **отчёт: [MAIL-AUDIT.md](MAIL-AUDIT.md)** (ошибки, несостыковки, устаревшие
  параметры, критические проблемы: мёртвый Freenom-домен, EOL-система,
  утечка паролей через `sasldb2`).
- Исправлены `opendkim.conf`, `opendmarc.conf`, `aliases`, `hosts`.
- Восстановлены и модернизированы утраченные конфиги (`postfix/`, `dovecot/`,
  `amavis/`, таблицы `opendkim/`, `postfix-policyd-spf-python/`) под
  **Ubuntu 24.04 LTS** (Postfix 3.8, Dovecot 2.3.21, amavis 2.13,
  OpenDMARC 1.4.2).
- Из репозитория удалены `sasldb2` (база паролей!) и `aliases.db`;
  добавлен `.gitignore`. Пароли требуется сменить, историю git — очистить
  (см. MAIL-AUDIT.md §1.3).

## Раскладка

| Путь | Компонент |
|------|-----------|
| `postfix/main.cf`, `postfix/master.cf` | MTA: приём/отправка, milters, Amavis-маршрутизация |
| `dovecot/` | IMAP + LMTP + Sieve (POP3 отключён) |
| `amavis/conf.d/` | фильтрация спама/вирусов |
| `opendkim.conf`, `opendkim/`, `default/opendkim` | DKIM-подпись |
| `opendmarc.conf`, `default/opendmarc` | проверка DMARC |
| `postfix-policyd-spf-python/` | SPF-проверка входящих |
| `aliases`, `mailname`, `hosts`, `hostname` | системная почтовая идентичность |
