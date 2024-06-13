import requests
import time

def test_update():
    url = 'http://localhost:5000/update'
    data = {
        'source': 'manager',
        'deliver_to': 'downloader',
        'operation': 'download_file'
    }
    response = requests.post(url, json=data)
    assert response.status_code == 200
    time.sleep(5)  # Подождите некоторое время, чтобы сервисы обработали запрос

if __name__ == "__main__":
    test_update()
