# ru-asn-list

Репозиторий автоматически генерирует и публикует `ru_asn.list` для Shadowrocket на основе официального RIPEstat endpoint для России:

- источник: `https://stat.ripe.net/data/country-resource-list/data.json?resource=ru`
- формат каждой строки: `IP-ASN,<number>`
- внутри файла нет `,DIRECT`, потому что стратегия маршрутизации задаётся в самом правиле Shadowrocket

Пример для Shadowrocket:

```ini
[Rule]
RULE-SET,<URL_НА_ЭТОТ_ФАЙЛ>,DIRECT
```

Возможны две схемы публикации:

1. `public repo + raw URL`

   `https://raw.githubusercontent.com/dennech/ru-asn-list/main/ru_asn.list`

2. `private repo + public Pages URL`

   `https://dennech.github.io/ru-asn-list/ru_asn.list`

Bootstrap репозитория сначала пытается использовать `private + public Pages`, а если это недоступно для аккаунта или настроек GitHub, автоматически переключается на `public + raw.githubusercontent.com`.

## Что лежит в репозитории

- `ru_asn.list` — итоговый rule-set для Shadowrocket
- `ru_asn.meta.json` — метаданные генерации: страна, источник, `query_time`, время генерации, количество ASN и SHA256
- `tools/generate_ru_asn.py` — генератор и валидатор на Python 3 со стандартной библиотекой
- `.github/workflows/update-ru-asn.yml` — ежедневное обновление и ручной запуск

## Локальный запуск

Сгенерировать корневые файлы:

```bash
python3 tools/generate_ru_asn.py
```

Сгенерировать корневые файлы и Pages-артефакты:

```bash
python3 tools/generate_ru_asn.py --publish-pages
```

Проверить итоговый `ru_asn.list`:

```bash
python3 tools/generate_ru_asn.py --check
```

Разрешить публикацию подозрительно большого падения количества ASN:

```bash
python3 tools/generate_ru_asn.py --force-large-change
```

## Ручной запуск workflow

Запуск без override:

```bash
gh workflow run update-ru-asn.yml -R dennech/ru-asn-list
```

Запуск с `force_large_change=true`:

```bash
gh workflow run update-ru-asn.yml -R dennech/ru-asn-list -f force_large_change=true
```

Workflow также запускается автоматически один раз в день. Для public-репозитория добавлен heartbeat-коммит не чаще раза в 30 дней, чтобы планировщик GitHub Actions не заснул из-за отсутствия активности.

## Проверка опубликованного URL

Через `curl`:

```bash
curl -fsSL https://raw.githubusercontent.com/dennech/ru-asn-list/main/ru_asn.list | sed -n '1,5p'
```

Или, если используется Pages:

```bash
curl -fsSL https://dennech.github.io/ru-asn-list/ru_asn.list | sed -n '1,5p'
```
