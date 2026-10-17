# Разбор событий Sysmon

Небольшой скрипт для практики с Windows Event Log: читает события запуска
процессов и сетевых соединений, собирает временную шкалу и отмечает совпадения
с тремя правилами. Нужен Python 3.11+, дополнительных библиотек нет.

## Как запустить

Команды выполняются из корня репозитория:

```sh
python projects/windows-threat-hunting/run.py --input projects/windows-threat-hunting/data/events.jsonl --output reports/windows.json --timeline-csv reports/windows-timeline.csv
python projects/windows-threat-hunting/run.py --input projects/windows-threat-hunting/data/sysmon.xml --output reports/windows-xml.json
python -m unittest discover -s projects/windows-threat-hunting/tests -v
```

В JSONL примере 12 событий и 3 срабатывания: по одному на каждое правило.
В XML примере 3 события и 2 срабатывания. CSV необязателен; в JSON есть
счётчики, срабатывания с поясняющими полями и вся временная шкала в UTC.

## Что проверяется

- WH001: PowerShell с `-e`, `-ec`, `-enc` или `-encodedcommand` и base64-подобным аргументом — MITRE ATT&CK T1059.001.
- WH002: Word, Excel, PowerPoint или Outlook запускает командный интерпретатор — T1204.002, T1059.
- WH003: PowerShell, wscript или cscript соединяется на порт 1337, 4444 или 9001 — T1059 и повод проверить Command and Control. Адреса 127.0.0.1 и ::1 исключены.

Это подсказки для проверки, срабатывание само по себе не означает атаку.
Сетевые события связываются с предыдущим запуском по `Computer + ProcessGuid`,
без подстановки по PID. `Image` из самого сетевого события имеет приоритет.

## Файлы и ограничения

`run.py` отвечает за командную строку и отчёты, `read_events.py` читает входные
данные, `analyze.py` строит шкалу и проверяет правила. В `data/` только
синтетические события: вымышленные GUID, компьютеры LAB и адреса TEST-NET.
Команды из журналов не исполняются и никуда не отправляются.

JSONL использует поля `timestamp` с часовым поясом, `event_id`, `computer`,
`process_guid`, `image`, `command_line`, `parent_image`, `destination_ip`
и `destination_port`. Поддерживаются и имена Sysmon: `UtcTime`, `EventID`,
`Image`, `CommandLine` и другие. XML должен быть экспортом Sysmon, не EVTX.
Обрабатываются только Event ID 1 и 3; файл целиком загружается в память.

В `sigma/` лежат experimental YAML правила. Python вручную повторяет их
небольшое подмножество, а не загружает YAML как Sigma backend; тесты сверяют
условия на примерах. Нет сбора живых логов и проверки в SIEM, возможны ложные
срабатывания и пропуски сложной обфускации PowerShell.

Дальше: добавить отдельный файл разрешённых исключений и больше примеров
команд PowerShell с кавычками, чтобы лучше понять границы первого правила.
