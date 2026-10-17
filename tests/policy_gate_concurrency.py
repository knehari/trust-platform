"""Two-session C-01 regression. Disposable PostgreSQL only; no signing keys.

Synchronization observes PostgreSQL's lock graph, not an assumed sleep duration.
Use --expect-vulnerable only against migrations 0001..0010.
"""
import argparse
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import psycopg

URL = os.environ['TRUST_CI_DATABASE_URL']


def connect():
    return psycopg.connect(URL, autocommit=True, options='-c statement_timeout=15000')


def scalar(db, sql, args=()):
    return db.execute(sql, args).fetchone()[0]


def fixture(db, dual):
    ca = uuid.uuid4()
    db.execute("INSERT INTO ca(ca_id,display_name,policy_version) VALUES(%s,'C01 lab','v1')", (ca,))
    req = scalar(db, "SELECT request_id FROM create_issuance_request(%s,%s,%s,'app','v1')", (ca, str(uuid.uuid4()), bytes([1])*32))
    for old, new in [('RECEIVED', 'CSR_VALIDATED'), ('CSR_VALIDATED', 'AUTHORIZED')]:
        db.execute('SELECT transition_issuance_request(%s,%s,%s,%s,\'app\')', (ca, req, old, new))
    db.execute("SELECT reserve_issuance_serial(%s,%s,'app')", (ca, req))
    if dual:
        root = bytes.fromhex('3003020101')
        obs = scalar(db, "SELECT register_ca_public_observation(%s,'observer',digest(%s,'sha256'),%s,%s)", (ca, root, bytes([2])*32, root))
        draft = scalar(db, """SELECT register_cp_cps_draft(%s,'author',%s,'lab-server','v1',
            '1.3.6.1.4.1.55555.1.1','v1',%s,'CP draft','CPS draft',
            digest('CP draft','sha256'),digest('CPS draft','sha256'))""", (ca, obs, bytes([3])*32))
        approval = scalar(db, """SELECT approve_policy_draft_lab(%s,%s,'maker','checker',
            digest('CP draft','sha256'),digest('CPS draft','sha256'),
            now()-interval '1 hour',now()+interval '1 hour')""", (ca, draft))
        db.execute("SELECT activate_ca_policy_gate_lab(%s,'operator')", (ca,))
        db.execute("SELECT grant_request_approved_policy_lab(%s,%s,%s,'1.3.6.1.4.1.55555.1.1',%s,'app')", (ca, req, approval, bytes([4])*32))
    return ca, req


def intent(db, ca, req, direct=False):
    if direct:
        db.execute("""INSERT INTO signing_intent(ca_id,request_id,signer_key_ref,tbs_sha256,policy_revision,operation_ref)
            VALUES(%s,%s,'lab-key',%s,'v1',%s)""", (ca, req, bytes([4])*32, str(req)))
    else:
        db.execute("SELECT * FROM create_signing_intent(%s,%s,'app','lab-key',%s,'v1',%s)", (ca, req, bytes([4])*32, str(req)))


def activate(db, ca, dual, direct=False):
    if direct:
        table = 'ca_dual_signature_enforcement' if dual else 'ca_policy_enforcement'
        db.execute(f'INSERT INTO {table}(ca_id) VALUES(%s)', (ca,))
    else:
        fn = 'require_dual_signature_policy_lab' if dual else 'activate_ca_policy_gate_lab'
        db.execute(f"SELECT {fn}(%s,'operator')", (ca,))


def outcome(fn):
    try:
        fn()
        return 'accepted'
    except psycopg.Error as exc:
        return exc.sqlstate


def wait_blocked(observer, waiter, blocker, future):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if scalar(observer, 'SELECT %s = ANY(pg_blocking_pids(%s))', (blocker, waiter)):
            return
        if future.done():
            raise AssertionError(f'operation completed before lock barrier: {future.result()}')
        time.sleep(0.01)
    raise AssertionError('lock barrier not reached')


def race(dual, isolation, reverse=False, direct=False, vulnerable=False):
    with connect() as observer, connect() as first, connect() as second, ThreadPoolExecutor(1) as pool:
        ca, req = fixture(observer, dual)
        first.execute('BEGIN')
        second.execute(f'BEGIN ISOLATION LEVEL {isolation}')
        # Establish snapshot before the first transaction changes the fence.
        second.execute('SELECT count(*) FROM ca').fetchone()
        if reverse:
            intent(first, ca, req, direct)
            task = lambda: activate(second, ca, dual, direct)
        else:
            activate(first, ca, dual, direct)
            task = lambda: intent(second, ca, req, direct)
        future = pool.submit(outcome, task)
        try:
            wait_blocked(observer, second.info.backend_pid, first.info.backend_pid, future)
        finally:
            first.execute('COMMIT')
        result = future.result(timeout=10)
        expected = 'accepted' if vulnerable else ('23514' if isolation == 'READ COMMITTED' else '40001')
        assert result == expected, (dual, isolation, reverse, direct, result, expected)
        second.execute('COMMIT' if result == 'accepted' else 'ROLLBACK')
        count = scalar(observer, 'SELECT count(*) FROM signing_intent WHERE ca_id=%s', (ca,))
        assert count == (1 if reverse or vulnerable else 0), count
        print(f'PASS: dual={dual} isolation={isolation} intent_first={reverse} direct={direct} result={result}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expect-vulnerable', action='store_true')
    args = parser.parse_args()
    if args.expect_vulnerable:
        for dual in (False, True):
            race(dual, 'READ COMMITTED', vulnerable=True)
        print('REPRODUCED C-01: both gates committed before unchecked intent completed')
    else:
        for dual in (False, True):
            for isolation in ('READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE'):
                for reverse in (False, True):
                    for direct in (False, True):
                        race(dual, isolation, reverse, direct)
