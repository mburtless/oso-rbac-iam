.PHONY: start
start:
	# docker up PG
	docker run -p 5432:5432 --name oso-pg -e POSTGRES_PASSWORD=mysecretpassword --rm -d postgres:9.6

.PHONY: bootstrap-db
bootstrap-db:
	# apply schema
	docker exec oso-pg psql -U postgres -c "CREATE ROLE oso WITH PASSWORD 'ososecretpwd' CREATEDB LOGIN;" postgres
	docker exec -i oso-pg /bin/bash -c "createdb --username oso oso-rbac-iam"
	docker exec -i oso-pg /bin/bash -c "PGPASSWORD=ososecretpwd psql -U oso oso-rbac-iam" < ./schema.sql
	# start binary

.PHONY: stop
stop:
	docker stop oso-pg

.PHONY: gen
gen:
	go generate