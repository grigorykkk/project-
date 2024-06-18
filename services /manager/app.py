from flask import Flask, request
from kafka import KafkaProducer, KafkaConsumer
import json
import threading

app = Flask(__name__)
producer = KafkaProducer(bootstrap_servers='kafka:9092',
                         value_serializer=lambda v: json.dumps(v).encode('utf-8'))

def listen_for_updates():
    consumer = KafkaConsumer('update_requests',
                             bootstrap_servers='kafka:9092',
                             auto_offset_reset='earliest',
                             value_deserializer=lambda x: json.loads(x.decode('utf-8')))
    for message in consumer:
        data = message.value
        if data['operation'] == 'download_file':
            producer.send('download_requests', data)
        elif data['operation'] == 'verification_requested':
            producer.send('verification_requests', data)
        elif data['operation'] == 'proceed_with_update':
            if data['verified']:
                producer.send('update_requests', data)

@app.route('/update', methods=['POST'])
def update():
    data = request.json
    producer.send('update_requests', data)
    return 'Update request sent', 200

if __name__ == "__main__":
    threading.Thread(target=listen_for_updates).start()
    app.run(host='0.0.0.0', port=5000)
