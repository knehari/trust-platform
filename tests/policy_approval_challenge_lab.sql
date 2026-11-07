-- V1.6 negative SQL tests; full parallel-consumption harness remains outstanding.
BEGIN;
DO $t$
DECLARE v_random UUID := gen_random_uuid();
        v_nonce BYTEA := digest('test challenge', 'sha256');
BEGIN
  IF consume_policy_approval_challenge_lab(
    v_random,v_random,v_random,v_nonce,'alice','bob',v_random)
  THEN RAISE EXCEPTION 'nonexistent challenge was consumed'; END IF;

  BEGIN
    PERFORM consume_policy_approval_challenge_lab(
      v_random,v_random,v_random,decode('00','hex'),'alice','bob',v_random);
    RAISE EXCEPTION 'malformed nonce accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

  BEGIN
    PERFORM consume_policy_approval_challenge_lab(
      v_random,v_random,v_random,v_nonce,'alice','alice',v_random);
    RAISE EXCEPTION 'same reviewer accepted';
  EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

  IF EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE table_name='policy_approval_challenge_lab'
      AND constraint_type='UNIQUE' AND constraint_name='policy_approval_challenge_lab_nonce_sha256_key'
  ) IS FALSE THEN
    RAISE EXCEPTION 'nonce replay uniqueness constraint missing';
  END IF;
END $t$;
ROLLBACK;
