// Reproduce the public synthetic fixture with Node's independent crypto provider.
// Never use these fixed keys, salt, or nonce outside this fixture.
import { pbkdf2Sync, createCipheriv } from 'node:crypto';
const password = 'synthetic setup export password only';
const plaintext = '{"version":1,"synthetic":true}';
const salt = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const cek = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 32));
const iv = Buffer.from(Array.from({ length: 12 }, (_, i) => i + 64));
const alg = 'PBES2-HS512+A256KW';
const header = { alg, enc: 'A256GCM', p2c: 220000, p2s: salt.toString('base64url'), typ: 'remozio-setup-v1+jwe' };
const protectedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
const kek = pbkdf2Sync(password, Buffer.concat([Buffer.from(alg), Buffer.from([0]), salt]), header.p2c, 32, 'sha512');
const wrap = createCipheriv('id-aes256-wrap', kek, Buffer.alloc(8, 0xa6));
const encryptedKey = Buffer.concat([wrap.update(cek), wrap.final()]);
const gcm = createCipheriv('aes-256-gcm', cek, iv);
gcm.setAAD(Buffer.from(protectedHeader, 'ascii'));
const ciphertext = Buffer.concat([gcm.update(plaintext, 'utf8'), gcm.final()]);
const compact = [protectedHeader, ...[encryptedKey, iv, ciphertext, gcm.getAuthTag()].map(value => value.toString('base64url'))].join('.');
console.log(JSON.stringify({ password, plaintext, compact }, null, 2));
