// Usage: npm install sm-crypto-v2@<version> in a clean dir, then: node repro.js <that dir>
// Prints observations only. It does not say whether a behaviour is a defect.
const dir = process.argv[2] || '.';
const {sm2, sm4} = require(dir + '/node_modules/sm-crypto-v2');
const version = require(dir + '/node_modules/sm-crypto-v2/package.json').version;
const key = '0123456789abcdeffedcba9876543210';
const msg = 'review packet message';
const ZERO = '00000000000000000000000000000000';
const R = {version};
const tryit = f => { try { return f(); } catch (e) { return {threw: String(e.message || e).slice(0, 90)}; } };

// Claim A: encryption without an iv silently uses an all-zero IV.
R.A_cbc_no_iv_equals_explicit_zero_iv = tryit(() =>
  sm4.encrypt(msg, key, {mode: 'cbc'}) === sm4.encrypt(msg, key, {mode: 'cbc', iv: ZERO}));
R.A_control_other_iv_differs = tryit(() =>
  sm4.encrypt(msg, key, {mode: 'cbc', iv: '11111111111111111111111111111111'}) !== sm4.encrypt(msg, key, {mode: 'cbc', iv: ZERO}));
R.A_gcm_no_iv_equals_explicit_zero_iv = tryit(() =>
  JSON.stringify(sm4.encrypt(msg, key, {mode: 'gcm'})) === JSON.stringify(sm4.encrypt(msg, key, {mode: 'gcm', iv: ZERO})));

// Claim B: GCM decryption of tampered ciphertext succeeds when no tag is passed.
const IV = '00112233445566778899aabbccddeeff';
R.B_gcm_tampered_no_tag = tryit(() => {
  const enc = sm4.encrypt(msg, key, {mode: 'gcm', iv: IV, output: 'array'});
  const ct = ArrayBuffer.isView(enc) || Array.isArray(enc) ? Array.from(enc) : Array.from(enc.output);
  const bad = ct.slice(); bad[0] ^= 1;
  const pt = sm4.decrypt(bad, key, {mode: 'gcm', iv: IV, output: 'array'});
  return {returned_bytes: Buffer.from(pt).toString('hex').slice(0, 32), original_hex: Buffer.from(msg).toString('hex').slice(0, 32)};
});
R.B_control_tampered_with_genuine_tag = tryit(() => {
  const enc = sm4.encrypt(msg, key, {mode: 'gcm', iv: IV, output: 'array', outputTag: true});
  const bad = Array.from(enc.output); bad[0] ^= 1;
  return {accepted: !!sm4.decrypt(bad, key, {mode: 'gcm', iv: IV, output: 'array', tag: enc.tag})};
});

// Claim C: sm2.doSignature on a raw message uses the message bytes as the digest by default.
const kp = sm2.generateKeyPairHex();
const sig = tryit(() => sm2.doSignature(msg, kp.privateKey));
R.C_default_signature_verifies_with_hash_true = tryit(() => sm2.doVerifySignature(msg, sig, kp.publicKey, {hash: true}));
R.C_default_signature_verifies_with_default = tryit(() => sm2.doVerifySignature(msg, sig, kp.publicKey));
R.C_control_hash_true_signature_verifies_with_hash_true = tryit(() =>
  sm2.doVerifySignature(msg, sm2.doSignature(msg, kp.privateKey, {hash: true}), kp.publicKey, {hash: true}));
console.log(JSON.stringify(R, null, 1));
