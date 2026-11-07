import type { Certificate } from './api';
import { canonicalSerialHex } from './serial.ts';

export function filterLoadedCertificates(certificates: Certificate[], rawQuery: string): Certificate[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return certificates;
  const serial = canonicalSerialHex(query);
  return certificates.filter(cert =>
    [cert.subject_cn ?? '', cert.serial_hex, cert.fingerprint_sha256, cert.request_id, cert.state]
      .some(value => value.toLowerCase().includes(query))
    || (serial !== null && cert.serial_hex.toLowerCase().includes(serial))
  );
}
