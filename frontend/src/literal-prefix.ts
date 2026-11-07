// Mirror management-api's literal_prefix input checks before sending a query.
export function normalizeLiteralPrefix(value: string): string {
  return value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
}

export function validLiteralPrefix(value: string): boolean {
  const characters = [...value];
  return characters.length >= 2
    && characters.length <= 255
    && !characters.some(character => /\p{Cc}/u.test(character));
}
