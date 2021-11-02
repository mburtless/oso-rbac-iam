.PHONY: start
start:
	# docker up PG
	docker run -p 5432:5432 --name oso-pg -e POSTGRES_PASSWORD=mysecretpassword --rm -d postgres:9.6
	# sleep until healthy
	sleep 5
	# apply schema
	docker exec -i oso-pg /bin/bash -c "psql -U postgres -c \"CREATE ROLE oso WITH PASSWORD 'ososecretpwd' CREATEDB LOGIN;\" postgres"
	docker exec -i oso-pg /bin/bash -c "createdb --username oso oso-rbac-iam"
	docker exec -i oso-pg /bin/bash -c "PGPASSWORD=ososecretpwd psql -U oso oso-rbac-iam" < ./schema.sql

.PHONY: stop
stop:
	docker stop oso-pg

.PHONY: gen
gen:
	go generate
