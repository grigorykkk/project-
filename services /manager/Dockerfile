# Установим базовый образ Python
FROM python:3.8-slim

# Установим зависимости
COPY requirements.txt .
RUN pip install -r requirements.txt

# Скопируем код сервиса
COPY . /app
WORKDIR /app

# Запустим приложение
CMD ["python", "app.py"]
