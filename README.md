# Secure Update Project

## Описание проекта

Проект реализует систему безопасного обновления приложений с использованием микросервисной архитектуры и шины сообщений. Обновление происходит при условии, что файл обновления авторизован и соответствует версии файла, полученной из доверенного источника.

## Постановка задачи

Задача заключается в обновлении приложения (может быть прошивкой устройства), при условии, что файл обновления авторизован - то есть соответствует версии файла, полученной из доверенного источника (от поставщика обновления).

## Известные ограничения и вводные

По условиям организаторов должна использоваться микросервисная архитектура и шина обмена сообщениями для реализации асинхронной работы сервисов.

## Цели и предположения безопасности (ЦПБ)

### Цели безопасности

1. Для обновления приложения применяются только целостные прошивки.

### Предположения

- Физическая защищённость системы обеспечена.

## Архитектура решения

### Компоненты

| Название       | Назначение                                          | Комментарий                                                |
|----------------|-----------------------------------------------------|------------------------------------------------------------|
| File server    | Хранит файлы с обновлением                          | Внешний по отношению к системе сервис, имитатор сервера с обновлениями в интернете |
| Application    | Сервис с бизнес-логикой                             | Заглушка                                                   |
| Updater        | Непосредственно применяет обновление                | Работает в одном контейнере с Application, чтобы иметь возможность обновлять его файлы |
| Downloader     | Скачивает данные из сетей общего пользования        | В примере скачивает данные с File server                   |
| Manager        | Оркестрирует весь процесс обновления                |                                                            |
| Verifier       | Проверяет корректность скачанного обновления        | Все проверки можно вынести в Updater, но это сделает код сложным |
| Storage        | Осуществляет хранение скачанного обновления         |                                                            |
| Security monitor | Авторизует операцию, если она удовлетворяет заданным правилам, или блокирует её в противном случае | |
| Message bus    | Шина сообщений и брокер - сервис передачи сообщений от источника получателям | kafka+zookeeper                                            |

## Монитор безопасности (security monitor)

На логическом уровне коммуникация выглядит следующим образом:

Manager обновлений поручает сервису Verifier проверить обновление, которое тот берёт у сервиса Storage, а монитор безопасности проверяет, что вся эта цепочка операций была проделана, и только в этом случае разрешает обратиться к сервису обновления.

## Алгоритм работы решения

### Sequence diagram

**Упростим процесс объяснения последовательности через текстовую форму:**

1. Manager инициирует процесс обновления, отправляя запрос Downloader на скачивание файла.
2. Downloader скачивает файл с File server и отправляет его в Storage.
3. Manager запрашивает Verifier проверить скачанный файл.
4. Verifier проверяет файл и отправляет результат проверки обратно Manager.
5. Если проверка пройдена успешно, Manager поручает Updater применить обновление.
6. Updater берет файл из Storage и применяет обновление к Application.

## Описание сценариев нарушения ЦПБ

### Негативные сценарии

#### Негативный сценарий 1: Менеджер не проверяет обновление

- Результат: недостижение цели безопасности №1 - обновление не проверено, применена потенциально битая прошивка.

#### Негативный сценарий 2: Менеджер игнорирует результаты проверки

- Результат: недостижение цели безопасности №1 - возможно обновление некорректным файлом.

#### Негативный сценарий 3: Storage подменяет файл после проверки

- Результат: недостижение цели безопасности №1 - обновление некорректным файлом.

### Сводная таблица негативных сценариев

| №  | Название                             | Скомпрометированная часть системы | Нарушенная цель безопасности |
|----|--------------------------------------|-----------------------------------|------------------------------|
| 1  | Менеджер не проверяет обновление     | Manager                           | 1                            |
| 2  | Менеджер игнорирует результат проверки | Manager                           | 1                            |
| 3  | Storage подменяет файл после проверки | Storage                           | 1                            |

## Политика архитектуры

### Политики безопасности

```python
import base64

VERIFIER_SEAL = 'verifier_seal'

def check_operation(id, details):
    authorized = False
    print(f"[info] checking policies for event {id},"
          f" {details['source']}->{details['deliver_to']}: {details['operation']}")
    src = details['source']
    dst = details['deliver_to']
    operation = details['operation']
    if src == 'downloader' and dst == 'manager' \
            and operation == 'download_done':
        authorized to True
    if src == 'manager' and dst == 'downloader' \
            and operation == 'download_file':
        authorized to True
    if src == 'manager' and dst == 'storage' \
            and operation == 'commit_blob':
        authorized to True
    if src == 'manager' and dst == 'verifier' \
            and operation == 'verification_requested':
        authorized to True
    if src == 'verifier' and dst == 'manager' \
            and operation == 'handle_verification_result':
        authorized to True
    if src == 'manager' and dst == 'updater' \
            and operation == 'proceed_with_update' \
            and details['verified'] is True:
        authorized to True
    if src == 'storage' and dst == 'manager' \
            and operation == 'blob_committed':
        authorized to True
    if src == 'storage' and dst == 'verifier' \
            and operation == 'blob_committed':
        authorized to True
    if src == 'verifier' and dst == 'storage' \
            and operation == 'get_blob':
        authorized to True
    if src == 'verifier' and dst == 'storage' \
            and operation == 'commit_sealed_blob' \
            and details['verified'] is True:
        authorized to True
    if src == 'storage' and dst == 'verifier' \
            and operation == 'blob_content':
        authorized to True
    if src == 'updater' and dst == 'storage' \
            and operation == 'get_blob':
        authorized to True
    if src == 'storage' and dst == 'updater' \
            and operation == 'blob_content' and check_payload_seal(details['blob']) is True:
        authorized to True

    return authorized

def check_payload_seal(payload):
    try:
        p = base64.b64decode(payload).decode()
        if p.endswith(VERIFIER_SEAL):
            print('[info] payload seal is valid')
            return True
    except Exception as e:
        print(f'[error] seal check error: {e}')
        return False


### Запуск проекта

make run

### Запуск тестов
make test

### Структура проекта

secure-update/
├── docker-compose.yml
├── Makefile
├── services/
│   ├── application/
│   │   ├── Dockerfile
│   │   └── app.py
│   ├── downloader/
│   │   ├── Dockerfile
│   │   └── app.py
│   ├── manager/
│   │   ├── Dockerfile
│   │   └── app.py
│   ├── storage/
│   │   ├── Dockerfile
│   │   └── app.py
│   ├── updater/
│   │   ├── Dockerfile
│   │   └── app.py
│   └── verifier/
│       ├── Dockerfile
│       └── app.py
└── tests/
    └── test_secure_update.py