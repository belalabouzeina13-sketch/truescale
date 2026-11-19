/* Vault — shared helpers for the order page and the studio.
   Final files are encrypted (AES-256-GCM) in the browser before upload.
   Each order's key is derived from the studio passphrase + order id,
   so the studio can always re-create an unlock link and nothing secret is stored online. */
const Vault = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();

  const b64 = buf => {
    const u = new Uint8Array(buf); let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64url = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64url = s => unb64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));

  async function master(passphrase){
    const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('baz-studio-v1'), iterations: 310000, hash: 'SHA-256' }, base, 256);
    return crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  }
  async function orderKeyRaw(masterKey, orderId){
    return crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('order:' + orderId) }, masterKey, 256);
  }
  const aesKey = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

  async function encrypt(key, data){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { iv: b64(iv), ct };
  }
  const decrypt = (key, iv, ct) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, ct);

  async function makeCheck(key){ const r = await encrypt(key, enc.encode('baz-ok')); return { iv: r.iv, ct: b64(r.ct) }; }
  async function testCheck(key, check){
    try { return dec.decode(await decrypt(key, check.iv, unb64(check.ct))) === 'baz-ok'; } catch (e) { return false; }
  }
  function randomId(n = 12){
    const a = 'abcdefghijkmnpqrstuvwxyz23456789', r = crypto.getRandomValues(new Uint8Array(n));
    return Array.from(r, x => a[x % a.length]).join('');
  }
  return { b64, unb64, b64url, unb64url, master, orderKeyRaw, aesKey, encrypt, decrypt, makeCheck, testCheck, randomId };
})();
