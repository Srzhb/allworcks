# Разбор сетевого трафика

Небольшой учебный проект на Python 3.11+, без сторонних библиотек.
Читает PCAP, показывает DNS и HTTP, ищет серии SYN на разные порты.
Ещё сверяет оповещения Suricata с конкретными пакетами и собирает
наблюдаемые домены, адреса и URL в JSON. Это кандидаты для проверки,
а не готовый вывод о вредоносности.

Запуск из корня репозитория:

```bash
python projects/network-analysis/run.py \
  --input projects/network-analysis/data/traffic.pcap \
  --eve projects/network-analysis/data/expected-alerts.eve.jsonl \
  --output reports/network.json
python -m unittest discover -s projects/network-analysis/tests -v
```

В примере 21 пакет: 4 DNS-сообщения, 2 HTTP-запроса,
одна серия SYN на 10 портов и 2 демонстрационных оповещения.
Файл `expected-alerts.eve.jsonl` создан генератором,
с пометкой `lab_fixture: true`. Это не вывод запущенной Suricata.
Для проверки используются номер пакета, адреса, порты, время и признаки правила.
Порог серии SYN по умолчанию — 8 разных портов за 10 секунд.

Что читать в коде:

- `pcap.py` — заголовки Ethernet, IPv4, TCP/UDP, DNS и HTTP.
- `analyze.py` — сводка, поиск SYN-серий и сопоставление оповещений.
- `run.py` — аргументы запуска и сохранение отчёта.
- `generate_demo.py` — создание того же примера с корректными checksums.
- `tests/` — 19 тестов, включая повреждённые данные и сохранность входных файлов.

Пересоздать пример можно так:

```bash
python projects/network-analysis/generate_demo.py \
  --output projects/network-analysis/data/traffic.pcap \
  --eve-output projects/network-analysis/data/expected-alerts.eve.jsonl
```

Все адреса и домены учебные; программа ничего не отправляет в сеть.
Поддерживается classic PCAP, Ethernet/один VLAN и IPv4. Нет PCAPNG,
сборки IP-фрагментов и TCP-потоков, TLS и проверки checksums анализатором.
DNS читается из UDP/53; HTTP-заголовки должны помещаться в один пакет.
Suricata и Zeek здесь не запускались. Для самостоятельной проверки есть
`rules/local.rules`, `zeek/lab.zeek` и фильтры в `wireshark/display-filters.txt`.
Настройка внешних инструментов: [Suricata](https://docs.suricata.io/), [Zeek](https://docs.zeek.org/).
