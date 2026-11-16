# Running the PostgreSQL test cases

Most API tests run on SQLite and need nothing. A few cases only mean something on
PostgreSQL, because SQLite has one writer: the lock-order and deadlock cases for
sign-in ties, the guest action recorded during an analysis, and the migration
check on PostgreSQL. Without a server they skip. In CI they always run, against
PostgreSQL 17, and a case that skips for want of a server fails the job.

## Run them on your machine

Start a throwaway server from the image Compose already uses. The password is a
placeholder for a database that holds nothing.

```sh
docker run -d --name nyctr-test-postgres -e POSTGRES_PASSWORD=local-only \
  -p 127.0.0.1:55432:5432 postgres:17-bookworm
```

Wait a few seconds, then point the tests at it. The address ends in `/`: each
case makes a database of its own on the server and drops it when it ends.

```sh
export NYCTR_TEST_POSTGRES='postgresql+psycopg://postgres:local-only@127.0.0.1:55432/'
PYTHONPATH=services/api python -m pytest services/api/tests tests/release tests/acceptance \
  --junitxml=test-results/api.xml
python scripts/postgres_cases.py test-results/api.xml
```

The last command prints how many PostgreSQL cases passed and exits with an error
if any skipped for want of the server, as CI does. Cases that skip because
SQLite has one writer are not counted against you.

To run only the PostgreSQL cases, add `-k postgresql` to the pytest line (the
guest action case has no such name; run `-k guest_action` too, or the whole suite).

Remove the server when you are done:

```sh
docker rm -f nyctr-test-postgres
```

Leave `NYCTR_TEST_POSTGRES` unset for the default SQLite run.
