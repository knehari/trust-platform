// Normalize a displayed hexadecimal serial to the positive DER-content form
// returned by the API. Decimal serials are deliberately ambiguous and unsupported.
export function canonicalSerialHex(raw: string): string | null {
  const input = raw.replace(/^0x/i, '');
  let hex: string;
  if (input.includes(':')) {
    const pairs = input.split(':');
    if (!pairs.every(pair => /^[0-9a-f]{2}$/i.test(pair))) return null;
    hex = pairs.join('');
  } else {
    hex = input;
  }
  if (!/^[0-9a-f]{1,40}$/i.test(hex)) return null;
  const magnitude = hex.replace(/^0+/, '');
  if (!magnitude) return null;
  let canonical = magnitude.length % 2 ? `0${magnitude}` : magnitude;
  if (parseInt(canonical.slice(0, 2), 16) >= 0x80) canonical = `00${canonical}`;
  return canonical.length <= 40 ? canonical.toLowerCase() : null;
}
