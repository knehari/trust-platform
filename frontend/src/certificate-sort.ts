import type { Certificate } from './api';

export type CertificateSort = 'newest' | 'oldest' | 'cn' | 'serial';

export function sortLoadedCertificates(rows: Certificate[], order: CertificateSort): Certificate[] {
  if (order === 'newest') return rows;
  if (order === 'oldest') return [...rows].reverse();
  return [...rows].sort((a, b) => {
    const comparison = order === 'cn'
      ? (a.subject_cn === null && b.subject_cn === null ? 0 : a.subject_cn === null ? 1 : b.subject_cn === null ? -1 : a.subject_cn.localeCompare(b.subject_cn))
      : a.serial_hex.localeCompare(b.serial_hex);
    return comparison || a.request_id.localeCompare(b.request_id);
  });
}
