.PHONY: build clean lint test

build: sql.tar.gz
sql.tar.gz:
	@tar czf sql.tar.gz api cdn

clean:
	@rm -f sql.tar.gz missing_pk.log

lint:
	@./lint.sh api
	@./lint.sh cdn

TEST_CDN_DB_HOST = $(if ${CDS_CDN_DATABASE_HOST},${CDS_CDN_DATABASE_HOST},localhost)
TEST_CDN_DB_PORT = $(if ${CDS_CDN_DATABASE_PORT},${CDS_CDN_DATABASE_PORT},5432)
TEST_CDN_DB_USER = $(if ${CDS_CDN_DATABASE_USER},${CDS_CDN_DATABASE_USER},cds)
TEST_CDN_DB_PASS = $(if ${CDS_CDN_DATABASE_PASS},${CDS_CDN_DATABASE_PASS},cds)
TEST_CDN_DB_NAME = $(if ${CDS_CDN_DATABASE_NAME},${CDS_CDN_DATABASE_NAME},cdn)

TEST_API_DB_HOST = $(if ${CDS_API_DATABASE_HOST},${CDS_API_DATABASE_HOST},localhost)
TEST_API_DB_PORT = $(if ${CDS_API_DATABASE_PORT},${CDS_API_DATABASE_PORT},5432)
TEST_API_DB_USER = $(if ${CDS_API_DATABASE_USER},${CDS_API_DATABASE_USER},cds)
TEST_API_DB_PASS = $(if ${CDS_API_DATABASE_PASS},${CDS_API_DATABASE_PASS},cds)
TEST_API_DB_NAME = $(if ${CDS_API_DATABASE_NAME},${CDS_API_DATABASE_NAME},cds)

test:
	@./test.sh ${TEST_CDN_DB_USER} ${TEST_API_DB_PASS} ${TEST_API_DB_NAME} ${TEST_API_DB_HOST} ${TEST_API_DB_PORT}
	@./test.sh ${TEST_CDN_DB_USER} ${TEST_CDN_DB_PASS} ${TEST_CDN_DB_NAME} ${TEST_CDN_DB_HOST} ${TEST_CDN_DB_PORT}
