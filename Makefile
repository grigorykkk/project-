run:
	docker-compose up -d

test:
	python tests/test_secure_update.py

clean:
	docker-compose down
