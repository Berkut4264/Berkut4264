# Аудит конфигурации почтового сервера (postfix + dovecot + opendkim + opendmarc + amavis)

**Дата аудита:** 2026-10-04
**Исходная система:** Ubuntu 19.10 «Eoan Ermine» (development branch!), домен `mymyblog.cf`, хост `mail`
**Стек (по метаданным etckeeper):** Postfix 3.4, Dovecot 2.3.4, amavisd-new 2.11/2.12, OpenDKIM 2.11, OpenDMARC 1.3.2, SpamAssassin, ClamAV, postfix-policyd-spf-python, fail2ban, certbot (плагин Cloudflare), zabbix-agent.

---

## 0. Важно: что на самом деле содержит репозиторий

Репозиторий — это **снапшот `/etc` под управлением etckeeper**, но в единственном коммите
(`Create README.md`) сохранены **только файлы верхнего уровня**. Каталоги `postfix/`,
`dovecot/`, `amavis/`, `opendkim/`, `spamassassin/` и т.д. **в git не попали** —
от них остались лишь имена и права в файле метаданных `.etckeeper`.

Поэтому аудит проведён в двух частях:

1. **Реально присутствующие файлы** (`opendkim.conf`, `opendmarc.conf`, `aliases`,
   `hostname`, `hosts`, `sasldb2`, `aliases.db`) — проанализированы и исправлены.
2. **Утраченные конфиги** — **восстановлены по метаданным etckeeper и современной
   документации** (Postfix 3.8 / Dovecot 2.3.21 / amavis 2.13 / OpenDKIM 2.11 /
   OpenDMARC 1.4.2, целевая ОС — Ubuntu 24.04 LTS) и положены на свои канонические
   места (`postfix/main.cf`, `dovecot/conf.d/…`, `amavis/conf.d/…`, …).

Если у вас сохранился сам старый сервер или его бэкап — заберите оттуда оригинальные
`postfix/main.cf`, `postfix/master.cf`, `dovecot/`, `amavis/conf.d/50-user` и сверьте
с восстановленными версиями (особенно карты `vhost`, `vmailbox`, `virtual` и
содержимое `/etc/dovecot/passwd`/`userdb`).

---

## 1. Критические проблемы (почта физически не может работать)

### 1.1 Домен `mymyblog.cf` мёртв
Домен зарегистрирован через **Freenom** (бесплатные зоны .tk/.ml/.ga/.cf/.gq).
Freenom прекратил регистрации в марте 2023 после иска Meta, а с **февраля 2024**
сайты и **почта на доменах .cf перестали работать** (зоны переходят к национальным
операторам). Т.е. MX/A/TXT-записи домена с высокой вероятностью давно недоступны,
и никакая настройка сервера это не исправит.

**Действия:** зарегистрировать обычный платный домен; все конфиги в репозитории
параметризованы — достаточно заменить `mymyblog.cf` → новый домен и
`mail.mymyblog.cf` → `mail.новыйдомен` во всех файлах (grep по репозиторию).

### 1.2 Ubuntu 19.10 — EOL с июля 2020
Система более 6 лет без обновлений безопасности (ядро, OpenSSL, Postfix, Dovecot…).
Хуже того, Eoan был **development-веткой**, а не LTS. Эксплуатировать открытый
в интернет почтовый сервер на ней нельзя.

**Действия:** чистая установка **Ubuntu 24.04 LTS** (или актуального 26.04 LTS)
и перенос конфигурации из этого репозитория. Все поставленные конфиги написаны
под версии пакетов Ubuntu 24.04.

### 1.3 Утечка паролей: `sasldb2` в публичном репозитории
`aliaseы.db` и **`sasldb2`** были закоммичены в git. `sasldb2` — это база паролей
Cyrus SASL для SMTP-AUTH; по умолчанию пароли в ней хранятся **в открытом виде**.
Репозиторий `Berkut4264/Berkut4264` публичный — пароли SMTP скомпрометированы.

**Исправлено:** файлы удалены из дерева, добавлен `.gitignore`.
**Осталось сделать вручную:**
1. **Сменить все пароли** почтовых ящиков (в любом случае — они 6+ лет не менялись).
2. Очистить историю git: `git filter-repo --path sasldb2 --invert-paths`
   (или `git filter-branch`) + force-push; иначе файл достаётся из истории.
3. Удалить `.db`-бинарники из будущих коммитов — они генерируются (`newaliases`).

---

## 2. Найденные ошибки в сохранившихся конфигах и их исправление

### 2.1 `opendkim.conf`
| # | Проблема | Критичность | Исправление |
|---|----------|-------------|-------------|
| 1 | Строка `OmitHeaders` оканчивалась мусором **`<Paste>`** — артефакт копипасты; opendkim получал несуществующий «заголовок» | ошибка конфигурации | удалено |
| 2 | В `OmitHeaders` были `Date`, `Message-ID` — исключение этих заголовков из подписи **ослабляет защиту от DKIM-replay** | безопасность | список сокращён до `Bcc, Resent-Bcc` |
| 3 | `Canonicalization relaxed/simple` — `simple` для тела ломает подпись при пересылке через рассылки/форвардеры | доставляемость | `relaxed/relaxed` |
| 4 | Нет `OversignHeaders From` — защита от переиспользования подписи (RFC 6376 §8.6) | безопасность | добавлено |
| 5 | `UMask 002` — нестандартно и открывает групповую запись | гигиена | `UMask 007` (стандарт Debian/Ubuntu) |
| 6 | Риск рассинхрона сокета: `Socket inet:8891@localhost` должен совпадать с `/etc/default/opendkim` и `smtpd_milters` | эксплуатация | создан `default/opendkim` с тем же сокетом; в main.cf заданы `inet:localhost:8891` |
| 7 | Длина ключа неизвестна (старые гайды генерировали 1024 бит — слабо с 2018) | безопасность | инструкция по генерации **2048 бит** + ротация селектора |

Что было корректно и сохранено: `SignatureAlgorithm rsa-sha256` (rsa-sha1 запрещён
RFC 8301), связка `KeyTable/SigningTable/TrustedHosts` через `refile:`, `Mode sv`,
TCP-сокет вместо unix-сокета (правильно для chroot-нутого `smtpd`).

### 2.2 `opendmarc.conf`
| # | Проблема | Критичность | Исправление |
|---|----------|-------------|-------------|
| 1 | `TrustedAuthservIDs mymyblog.cf` **не совпадает** с authserv-id сервера (имя хоста). Свои же `Authentication-Results` от OpenDKIM не доверялись → DMARC-оценка работала неправильно | ошибка логики | `AuthservID HOSTNAME` + `TrustedAuthservIDs HOSTNAME` |
| 2 | `PublicSuffixList /usr/share/publicsuffix` — указан **каталог** вместо файла | ошибка | `/usr/share/publicsuffix/public_suffix_list.dat` |
| 3 | `Socket local:/var/run/opendmarc/opendmarc.sock` — unix-сокет **недоступен** из chroot `smtpd` Postfix | ошибка архитектуры | `Socket inet:8893@localhost` (+ `default/opendmarc`, main.cf) |
| 4 | OpenDMARC 1.3 не проверял SPF сам; доверие чужим A-R заголовкам | безопасность | `SPFSelfValidate true` + `SPFIgnoreResults true` (>=1.4) |
| 5 | `RejectFailures` закомментирован (false) — DMARC-политики отправителей не исполнялись | безопасность | `true` (с оговоркой про этап внедрения) |
| 6 | Нет защиты от проверки своих submission-клиентов | гигиена | `IgnoreAuthenticatedClients true`, `IgnoreHosts` |
| 7 | Не конфигурировалась история для агрегированных отчётов (при этом `dbconfig-common/opendmarc.conf` в системе был!) | улучшение | `HistoryFile` + комментарии |

### 2.3 `hostname` / `hosts`
- `/etc/hostname` = `mail`, а в `/etc/hosts` **вообще нет записи для собственного имени** — ни FQDN, ни короткого. Итог: `gethostname()` не резолвится, кривой HELO у локально сгенерированной почты (bounce'ы, cron-отчёты), предупреждения в логах.
- **Исправлено:** добавлена `127.0.1.1 mail.mymyblog.cf mail` + инструкция заменить на публичный IP; рекомендация держать hostname в виде FQDN. В main.cf `myhostname` задан явно — это страхует даже при кривом `/etc/hosts`.

### 2.4 `aliases`
- Был только `root: postmaster@mymyblog.cf`. Отсутствовали обязательные по RFC 2142
  алиасы `postmaster`, `abuse` (Gmail/Mail.ru при рассмотрении репутации и abuse-десках
  ожидают их наличие), `MAILER-DAEMON`.
- Риск: если ящик `postmaster@mymyblog.cf` не существует в карте `vmailbox`,
  письма root'у теряются; если домен оказался бы в `mydestination` — петля.
- **Исправлено:** добавлены стандартные алиасы и предупреждающий комментарий.

### 2.5 Прочее из метаданных (что стоило проверить на живом сервере)
- `dovecot/dh.pem`, `dovecot/server-private.pem`, `postfix/server-private.pem` лежали с правами
  `0644` — приватные ключи, читаемые всеми. При переносе — `0600 root` / отдельные владельцы.
- `dkimkeys/` (0700, opendkim) **и** `opendkim/keys/…` — ключи дублировались в двух местах;
  оставлена одна каноническая схема (`/etc/opendkim/keys/<домен>/`).
- `letsencrypt/cloudflareapi.cfg` 0600 — ок, но добавлен в `.gitignore` (токен API в открытом виде).
- `postfix/main.cf.bak` — держать бэкапы конфигов рядом с боевыми — мусор; для этого есть git.

---

## 3. Что исправлено и создано в этой ветке

**Исправлены на месте:**
- `opendkim.conf`, `opendmarc.conf` — см. таблицы выше
- `aliases` — стандартный набор алиасов
- `hosts` — резолв собственного FQDN
- `.gitignore` — секреты и генерируемые файлы; удалены `sasldb2`, `aliases.db`

**Восстановлены/написаны заново (по метаданным etckeeper + современная документация):**

| Файл | Назначение |
|------|-----------|
| `postfix/main.cf` | MTA: виртуальные домены/ящики, Dovecot-SASL, TLS ≥1.2 (`smtpd_tls_protocols = >=TLSv1.2` вместо устаревших `smtpd_use_tls`, ручных btree-кэшей, `tls_random_source`), restrictions, milters 8891/8893, policyd-spf, лимиты |
| `postfix/master.cf` | :25 → Amavis 10024, reinject 10025 (no_milters/no_header_body_checks), submission 587 (TLS обязателен), **smtps 465 (RFC 8314)**, policyd-spf |
| `dovecot/dovecot.conf`, `conf.d/10-auth.conf`, `10-mail.conf`, `10-master.conf`, `10-ssl.conf`, `20-lmtp.conf`, `90-sieve.conf`, `15-mailboxes.conf` | IMAP(993/143+STARTTLS)+LMTP+Sieve; POP3 выключен (как было); passwd-file auth → vmail; `ssl_min_protocol = TLSv1.2` вместо устаревшего `ssl_protocols`; сокеты в chroot Postfix; памятка по синтаксису Dovecot 2.4 |
| `amavis/conf.d/05-domain_id`, `15-content_filter_mode`, `50-user` | фильтрация включена (bypass-строки закомментированы!), reinject на 10025, пороги SA, DKIM-подписание выключено (подписывает OpenDKIM), `D_DISCARD` вместо bounce |
| `opendkim/TrustedHosts`, `opendkim/KeyTable`, `opendkim/SigningTable` | шаблоны таблиц, к которым обращался opendkim.conf |
| `default/opendkim`, `default/opendmarc` | синхронизация сокетов с milter-конфигами и main.cf |
| `postfix-policyd-spf-python/policyd-spf.conf` | SPF-проверка входящих (TestOnly=1 на время отладки) |
| `mailname` | `mymyblog.cf` (требуется Amavis 05-domain_id) |

**Устаревшие конструкции, которые гарантированно встречались в конфигах 2019 года и которых в новых версиях нет** (checklist для сверки с бэкапом):

- Postfix: `smtpd_use_tls/smtp_use_tls` → `smtpd_tls_security_level`/`smtp_tls_security_level`
  ([DEPRECATION_README](https://www.postfix.org/DEPRECATION_README.html)); нас ждёт предупреждение
  `postconf: warning: support for parameter "smtpd_use_tls" will be removed`.
- Postfix: `tls_random_source = dev:/dev/urandom` — не нужен с OpenSSL ≥ 1.1.1.
- Postfix: `smtpd_tls_dh1024_param_file = /etc/postfix/dhparams.pem` — не нужен с Postfix ≥ 3.1.
- Postfix: списки протоколов `!TLSv1 !TLSv1.1` → `>=TLSv1.2` (Postfix ≥ 3.6).
- Dovecot: `ssl_protocols = !SSLv3 …` → `ssl_min_protocol = TLSv1.2` (2.3+).
- Dovecot 2.4 (будущее): `ssl_cert/ssl_key/ssl_dh` → `ssl_server_cert_file/…` без `<`;
  `disable_plaintext_auth=yes` → `auth_allow_cleartext=no` — см. `dovecot/conf.d/10-ssl.conf`.
- ManageSieve: порт 2000 → 4190.
- SASL auxprop `sasldb2` → passwd-file Dovecot (`/etc/dovecot/passwd`) — единая база
  паролей для IMAP и SMTP (на старом сервере они, судя по всему, жили раздельно!).

---

## 4. Чек-лист развёртывания (новый сервер, Ubuntu 24.04 LTS)

```bash
# 1. Пакеты
apt install postfix postfix-pcre postfix-policyd-spf-python \
            dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved \
            opendkim opendkim-tools opendmarc \
            amavisd-new spamassassin clamav-daemon certbot

# 2. Системное
hostnamectl set-hostname mail.НОВЫЙ-ДОМЕН
echo "<публичный_IP> mail.НОВЫЙ-ДОМЕН mail" >> /etc/hosts
useradd -r -u 5000 -g 5000 -s /usr/sbin/nologin vmail || groupadd -g 5000 vmail && useradd -r -u 5000 -g vmail -s /usr/sbin/nologin vmail
mkdir -p /var/mail/vhosts && chown -R vmail:vmail /var/mail/vhosts

# 3. Раскатать конфиги из репозитория по /etc, заменив mymyblog.cf -> НОВЫЙ-ДОМЕН
grep -rl 'mymyblog\.cf' .   # список файлов для правки

# 4. Пароли ящиков (новые! — старые скомпрометированы через sasldb2)
doveadm pw -s SHA512-CRYPT        # хэш -> /etc/dovecot/passwd: user@domain:{SHA512-CRYPT}...

# 5. DKIM-ключ (2048 бит)
mkdir -p /etc/opendkim/keys/НОВЫЙ-ДОМЕН
opendkim-genkey -b 2048 -d НОВЫЙ-ДОМЕН -D /etc/opendkim/keys/НОВЫЙ-ДОМЕН -s mail -v
chown opendkim:opendkim /etc/opendkim/keys/НОВЫЙ-ДОМЕН/mail.private
cat /etc/opendkim/keys/НОВЫЙ-ДОМЕН/mail.txt    # -> TXT-запись mail._domainkey в DNS

# 6. Карты Postfix и алиасы
printf 'НОВЫЙ-ДОМЕН\tplaceholder\n' > /etc/postfix/vhost
# vmailbox: user@НОВЫЙ-ДОМЕН  НОВЫЙ-ДОМЕН/user/   (обязателен слэш в конце)
# virtual:  info@НОВЫЙ-ДОМЕН  user@НОВЫЙ-ДОМЕН
postmap /etc/postfix/vhost /etc/postfix/vmailbox /etc/postfix/virtual
newaliases

# 7. DH-параметры Dovecot
openssl dhparam -out /etc/dovecot/dh.pem 2048

# 8. TLS: certbot --nginx -d mail.НОВЫЙ-ДОМЕН (+ deploy-hook: systemctl reload postfix dovecot)

# 9. Проверки
postconf -n && postfix check
doveconf -n
amavisd-new configtest / amavisd-new debug
opendkim-testkey -d НОВЫЙ-ДОМЕН -s mail -vvv
systemctl enable --now postfix dovecot opendkim opendmarc amavis
```

**DNS-чеклист (без этого почта будет уходить в спам/отклоняться):**

| Запись | Значение |
|--------|----------|
| `A` / `AAAA` `mail` | IP сервера |
| `MX` | `mail.НОВЫЙ-ДОМЕН` (приоритет 10) |
| `PTR` у провайдера/VPS | IP → `mail.НОВЫЙ-ДОМЕН` (и для IPv6!) |
| `TXT` SPF | `v=spf1 mx -all` |
| `TXT` `mail._domainkey` | из `mail.txt` (`v=DKIM1; k=rsa; p=…`) |
| `TXT` `_dmarc` | старт: `v=DMARC1; p=quarantine; rua=mailto:postmaster@НОВЫЙ-ДОМЕН; fo=1; adkim=s; aspf=s` → через 2–4 недели `p=reject` |

**Тесты:** <https://www.mail-tester.com>, `swaks --to …`, проверка `opendkim-testkey`,
`openssl s_client -connect mail.домен:993`, отправка с Gmail и анализ заголовков
`Authentication-Results` (spf/dkim/dmarc = pass).

---

## 5. Рекомендации дальше (по приоритету)

1. **Смена домена и паролей** — без этого всё остальное бессмысленно.
2. Очистить git-историю от `sasldb2` (см. §1.3).
3. Feedback loop + мониторинг DMARC-отчётов (`rua`), которые теперь собираются через OpenDMARC.
4. fail2ban (правила для postfix-sasl/dovecot уже были в старой системе — вернуть).
5. Опционально: MTA-STS/TLS-RPT и DANE (если DNSSEC у регистратора доступен) —
   современный уровень защиты SMTP-транспорта.
6. Отдельный DKIM-селектор и его ротация раз в год.
