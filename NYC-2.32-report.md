# NYC-2.32 report

Branch `ci/postgres-tests` (from origin/main c25d35a). Not pushed; no pull request.

## Commits
- 40359ab Run the PostgreSQL test cases in CI against PostgreSQL 17, and fail the job if one skips
- e8a1bd5 Fail the PostgreSQL check when no case named for PostgreSQL ran, and say what it counts

## Files and added lines (no test files touched; 111 added, 0 tests)
- `.github/workflows/ci.yml` +16 (service container, variable, check step)
- `scripts/postgres_cases.py` +53 (helper)
- `docs/testing/postgresql.md` +42

## Acceptance criteria
- AC-1: `backend` job gets a `postgres:17-bookworm` service (ci.yml, services block) and `NYCTR_TEST_POSTGRES` on the pytest step; the whole API suite runs once, so the PostgreSQL cases run in the same pass. The helper writes the count to `$GITHUB_STEP_SUMMARY`. Local run against postgres:17-bookworm: 34 of the 35 former skips now pass (1147 passed, 1 skipped, 0 failed). Test: that run; the first skip list (35) is the proof they do not run without the server. Caveat: the count the summary shows is cases with "postgresql" in the name (32); the guest action case and two "never wait for each other" cases have no such name, so the true figure is 34.
- AC-2: helper exits 1 for any skip whose message names `NYCTR_TEST_POSTGRES`; a SQLite-only skip does not fail. Proof, locally (no push, so not a throwaway CI commit): the SQLite-only run's junit gives exit 1 listing 34 cases; a probe test that skips with that message gives exit 1; with the probe skip removed, exit 0. A real CI throwaway commit is not done.
- AC-3: Added time. Local, loaded machine: 1122 s without PostgreSQL (1049 tests in services/api/tests), 1463 s with it (1148 tests incl. tests/release and tests/acceptance), so about +5.7 min locally, but the loads differed (another worker was running), so this is not a clean figure. Expected on a CI runner: about 15 s for the service to start plus the 34 cases; I could not measure it on GitHub. The job's timeout is 10 minutes; the unloaded runtime is unknown to me, and locally the suite takes 19 to 24 minutes under load. Check the first CI run.
- AC-4: `docs/testing/postgresql.md`.

## Checks on the tip (e8a1bd5)
- ruff (exact command): pass
- pytest, no PostgreSQL named: 1113 passed, 35 skipped, 0 failed, 1365 s
- format:check: pass
- web test: 302 passed (run again after the API run finished; the first run overlapped it)
- build: pass
- git diff --check: pass
Second-writer test: my change contains no check followed by a write, so it does not apply.

## Decisions left open
1. `test_a_device_being_filed_while_a_batch_reads_it_is_kept_on_postgresql` (services/api/tests/test_what_has_left.py:667) is PostgreSQL-only but uses the SQLite `world` fixture and never reads the variable, so it skips even in the new job, and its message does not name the variable. The helper does not fail on it. Making it run is a test change, which is out of scope. Needs a follow-up.
2. Whether to add a 10-minute timeout increase for the backend job (see AC-3).
3. Exact count: a pytest plugin or a named-case list would give 34; I used the name.

## Not done
No push or CI run; AC-2 not proven on a throwaway CI commit; AC-3 not measured on GitHub; no pull request text. The PostgreSQL container and volume were removed by name; no prune.
