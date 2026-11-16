import pytest


def test_proof_a_postgresql_case_that_skips():
    pytest.skip("No PostgreSQL server is named in NYCTR_TEST_POSTGRES")
