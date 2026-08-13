![Python](https://img.shields.io/badge/Python-3.11-blue)
![License](https://img.shields.io/badge/License-MIT-green)

# 🌐 Subdomain Finder

Поиск поддоменов через DNS bruteforce и пассивные источники.

## Возможности

- Перебор 400+ популярных поддоменов
- Пассивный поиск (crt.sh, AlienVault)
- Проверка HTTP/HTTPS
- Определение серверов и заголовков
- Многопоточность (50+ потоков)

## Установка

```bash
git clone https://github.com/Oncillaa/subdomain-finder.git
cd subdomain-finder
python subdomain_finder.py
```
⚠️ Только для образовательных целей

## 🔧 Как это работает

1. Перебирает 400+ популярных поддоменов
2. Параллельно ищет в пассивных источниках
3. Проверяет DNS и HTTP/HTTPS
4. Выводит найденные поддомены с IP и сервером

## 🔜 Планы

- [ ] Больше словарей
- [ ] Интеграция с Shodan
- [ ] Графический интерфейс
