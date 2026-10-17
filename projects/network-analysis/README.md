# Network Analysis Lab

Учебный проект для портфолио: офлайн-анализ PCAP, DNS/HTTP, поиск кандидатов на сканирование портов и сопоставление пакетов с IDS-оповещениями. Реализован на Python 3.11+ без сторонних библиотек. Все адреса взяты из диапазонов документации RFC 5737, домены используют зарезервированную зону `.test`. Генератор записывает файлы и не отправляет пакеты в сеть.

Проект демонстрирует навыки, указанные в резюме; это самостоятельный учебный стенд, а не подтверждение работы с реальными инцидентами или инфраструктурой работодателя.

## Быстрый запуск

Команды выполняются из корня репозитория:

```bash
python projects/network-analysis/run.py \
  --input projects/network-analysis/data/traffic.pcap \
  --eve projects/network-analysis/data/expected-alerts.eve.jsonl \
  --output reports/network.json
python -m unittest discover -s projects/network-analysis/tests -v
```

Ожидаемая сводка: **21 пакет, 4 DNS-сообщения, 2 HTTP-запроса, 1 кандидат на сканирование, 2 сопоставленных демонстрационных оповещения**. JSON содержит номера пакетов для проверки результатов в Wireshark.

Данные уже включены в репозиторий. Их можно воспроизвести побайтово:

```bash
python projects/network-analysis/generate_demo.py \
  --output projects/network-analysis/data/traffic.pcap \
  --eve-output projects/network-analysis/data/expected-alerts.eve.jsonl
```

`expected-alerts.eve.jsonl` — **искусственная ожидаемая выборка**, созданная генератором с полем `lab_fixture: true`. Это не результат запуска Suricata и не полный список возможных событий IDS. Анализатор сохраняет происхождение каждого оповещения в отчёте.

## Сценарий и проверка доказательств

| Пакеты | Событие | Что проверяет анализатор |
| --- | --- | --- |
| 1–2 | `updates.example.test` → A `203.0.113.20` | DNS-вопрос, сжатое имя ответа, TTL, адрес |
| 3–4 | `beacon.example.test` → NXDOMAIN | Демонстрационное совпадение DNS и код ответа 3 |
| 5–7 | TCP handshake | Контекст HTTP-соединения для внешних инструментов |
| 8–11 | `/health`, `/download/test-payload.exe`, пустые ответы | Два HTTP/1.1 запроса с Host и User-Agent |
| 12–21 | SYN от `198.51.100.42` к 10 портам `192.0.2.20` | Уникальные порты в скользящем окне |

Для оповещений проверяются `pcap_cnt`, IP-адреса, порты, протокол и время с допуском 10 мкс. Для SID 1000001/1000002 дополнительно проверяются DNS-имя и суффикс HTTP URI соответственно. В отчёте различаются несовпадение tuple, времени, полезной нагрузки, неизвестный SID и отсутствие ссылки на пакет. При неизвестном SID совпадение соединения не означает проверку правила IDS.

Порог сканирования по умолчанию — минимум 8 разных портов одного узла за 10 секунд от одного источника. Повторный SYN к тому же порту не увеличивает число портов; SYN+ACK исключён. Это эвристика возможного сканирования, которая не устанавливает намерение или успешность соединений.

`ioc_candidates` содержит наблюдаемые домены, IP, HTTP Host и URL с номерами пакетов. Пометка `observed_not_adjudicated` означает, что вредоносность не установлена. Совпадение `.exe` также не доказывает загрузку файла: в стенде ответы имеют пустое тело.

## Suricata: отдельная внешняя проверка

Suricata не нужна для основного запуска. Правила `rules/local.rules` предназначены для Suricata 7+. Внешние команды ниже приведены для воспроизведения; **Suricata и Zeek в этой среде не запускались**, их синтаксис и фактические срабатывания здесь не проверены.

При установленной Suricata и стандартном конфигурационном файле:

```bash
mkdir -p reports/suricata
suricata -T -c /etc/suricata/suricata.yaml \
  -S projects/network-analysis/rules/local.rules
suricata --runmode single -c /etc/suricata/suricata.yaml \
  -r projects/network-analysis/data/traffic.pcap \
  -S projects/network-analysis/rules/local.rules \
  -l reports/suricata
python projects/network-analysis/run.py \
  --input projects/network-analysis/data/traffic.pcap \
  --eve reports/suricata/eve.json \
  --output reports/network-suricata.json
```

Убедитесь, что в вашей конфигурации включены EVE JSON и тип события `alert`. `pcap_cnt` добавляется Suricata при офлайн-чтении PCAP; если версия/конфигурация его не записывает, анализатор честно выдаст `no_packet_reference`. Отдельные версии/настройки движка могут выдавать дополнительные или иначе привязанные оповещения. Требуется проверить `packet_alert_verification` и соответствующие пакеты вручную.

## Zeek и Wireshark

Пример запуска Zeek из корня репозитория:

```bash
mkdir -p reports/zeek
cd reports/zeek
zeek -r ../../projects/network-analysis/data/traffic.pcap \
  ../../projects/network-analysis/zeek/lab.zeek
cd ../..
```

В `dns.log` ожидаются два DNS-обмена, в `http.log` — два запроса. В `conn.log` можно исследовать TCP-соединения и незавершённые SYN. Это ориентиры для самостоятельной проверки, а не зафиксированный результат запуска Zeek.

Откройте `data/traffic.pcap` в Wireshark и используйте display filters из `wireshark/display-filters.txt`. Фильтр `frame.number == 3 || frame.number == 10` показывает пакеты из демонстрационной EVE-выборки. `tcp.stream eq 0` выделяет HTTP-разговор в исходном стенде.

## Границы реализации

- Classic PCAP v2.4: оба порядка байтов, микросекунды/наносекунды; Ethernet и один тег VLAN; IPv4 TCP/UDP. PCAPNG, IPv6 transport и другие link types не поддерживаются.
- Нет IP-дефрагментации, TCP-reassembly, расшифрования TLS и проверки контрольных сумм анализатором. Генератор создаёт корректные IPv4/TCP/UDP checksums; это проверяется тестом.
- DNS разбирается только поверх UDP/53, включая compression pointers, A/AAAA и имена в NS/CNAME/PTR. Поддержка AAAA-записи DNS не означает поддержку IPv6-пакетов. Максимум 256 записей на сообщение.
- HTTP/1.0–1.1: заголовки запроса должны полностью помещаться в один TCP-пакет. Ответы, тела, HTTP/2 и зашифрованный HTTP не анализируются. Повторно захваченные пакеты не дедуплицируются в DNS/HTTP-сводке.
- Повреждённые пакеты дают предупреждения; повреждённый контейнер PCAP останавливает запуск. Лимиты: 16 МиБ на пакет, 1 миллион пакетов, 64 КиБ HTTP-заголовков. Пакеты и результаты хранятся в памяти; для больших дампов нужен потоковый промышленный анализатор.
- Корреляция демонстрационных SID проверяет ограниченные признаки пакета и не воспроизводит нормализацию и всю логику Suricata.
- Проект не запускает live capture, не сканирует сеть и не блокирует адреса.

## Структура

```text
network_lab/pcap.py       # Ограниченный PCAP и протокольный парсер
network_lab/analysis.py   # Наблюдения, SYN-эвристика, EVE-корреляция
network_lab/fixture.py    # Детерминированный стенд без сетевых операций
network_lab/cli.py        # Аргументы и JSON-отчёт
data/                    # Синтетический PCAP и ожидаемая EVE-выборка
rules/                   # Два локальных демонстрационных правила Suricata
zeek/                    # Загрузка DNS/HTTP-анализаторов
wireshark/               # Display filters
tests/                   # unittest, повреждённые данные и сквозная проверка
```
