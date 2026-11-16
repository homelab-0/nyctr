# Running the PostgreSQL test cases

Most API tests run on SQLite and need nothing. A few cases only mean something on
PostgreSQL, because SQLite has one writer: the lock-order and deadlock cases for
sign-in ties, the guest action recorded during an analysis, the device filing
case and the migration check on PostgreSQL. Every such test carries the
`postgres` marker. Without a server they skip. In CI they always run, against
PostgreSQL 17, and a marked case that does not pass fails the job. So does a run
where fewer than 63 marked cases passed, so a test cannot lose its marker unseen.

When you add a test that needs a server, mark it with `@pytest.mark.postgres`
(or `pytest.param("postgresql", marks=pytest.mark.postgres)` in a parameter
list), and raise `--minimum` in `.github/workflows/ci.yml` by the number of
cases you added.

## Run them on your machine

Start a throwaway server from the image Compose already uses. The password is a
placeholder for a database that holds nothing. Pick any free port on your
machine in place of `55432`, and any container name that is not in use.

```sh
docker run -d --name nyctr-test-postgres -e POSTGRES_PASSWORD=local-only \
  -p 127.0.0.1:55432:5432 postgres:17-bookworm
until docker exec nyctr-test-postgres pg_isready -h 127.0.0.1 -U postgres; do sleep 1; done
```

Then point the tests at it. The address ends in `/`: each case makes a database
of its own on the server and drops it when it ends.

```sh
export NYCTR_TEST_POSTGRES='postgresql+psycopg://postgres:local-only@127.0.0.1:55432/'
PYTHONPATH=services/api python -m pytest services/api/tests tests/release tests/acceptance \
  --junitxml=test-results/api.xml
python scripts/postgres_cases.py test-results/api.xml --minimum 63
```

The last command prints how many marked cases passed and exits with an error if
any did not, as CI does.

To run only these cases, add `-m postgres` to the pytest line.

Remove the server when you are done:

```sh
docker rm -f nyctr-test-postgres
```

Leave `NYCTR_TEST_POSTGRES` unset for the default SQLite run.
