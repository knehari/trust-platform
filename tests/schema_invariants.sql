-- Executed against a disposable PostgreSQL database in GitHub CI.
-- This tests constraints and audit append-only behavior, not durability or HSM atomicity.
BEGIN;

INSERT INTO ca (ca_id, display_name, policy_version)
VALUES
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'Lab CA A', 'v1'),
    ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'Lab CA B', 'v1');

INSERT INTO certificate_request (
    request_id, ca_id, idempotency_key, csr_sha256,
    requester_id, policy_version, state
)
VALUES
    (
        '11111111-1111-4111-8111-111111111111',
        'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        'request-a', decode(repeat('01', 32), 'hex'),
        'lab-user', 'v1', 'AUTHORIZED'
    ),
    (
        '22222222-2222-4222-8222-222222222222',
        'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        'request-b', decode(repeat('02', 32), 'hex'),
        'lab-user', 'v1', 'AUTHORIZED'
    );

INSERT INTO serial_reservation (ca_id, request_id, serial_der_content)
VALUES (
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    '11111111-1111-4111-8111-111111111111',
    decode('01', 'hex')
);

-- Reject a zero serial number.
DO $test$
BEGIN
    BEGIN
        INSERT INTO serial_reservation (ca_id, request_id, serial_der_content)
        VALUES (
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            '22222222-2222-4222-8222-222222222222',
            decode('00', 'hex')
        );
        RAISE EXCEPTION 'zero serial was accepted';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;
END
$test$;

-- Prevent mixing a CA with another CA's request.
DO $test$
BEGIN
    BEGIN
        INSERT INTO serial_reservation (ca_id, request_id, serial_der_content)
        VALUES (
            'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            '22222222-2222-4222-8222-222222222222',
            decode('02', 'hex')
        );
        RAISE EXCEPTION 'issuer/request mismatch was accepted';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;
END
$test$;

INSERT INTO audit_event (event_id, actor_id, event_type, decision)
VALUES ('33333333-3333-4333-8333-333333333333', 'lab-user', 'request.received', 'allow');

DO $test$
BEGIN
    BEGIN
        UPDATE audit_event SET decision = 'tampered'
        WHERE event_id = '33333333-3333-4333-8333-333333333333';
        RAISE EXCEPTION 'audit mutation was accepted';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM <> 'audit_event records may not be updated or deleted' THEN
            RAISE;
        END IF;
    END;
END
$test$;

ROLLBACK;
