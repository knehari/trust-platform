const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function canonicalUuid(raw: string): string | null {
  let value = raw.trim();
  if (/^urn:uuid:/i.test(value)) value = value.slice(9);
  if (value.startsWith('{') && value.endsWith('}')) value = value.slice(1, -1);
  return uuidPattern.test(value) ? value.toLowerCase() : null;
}
