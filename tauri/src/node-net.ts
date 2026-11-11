const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEX = /^[0-9a-fA-F]{1,4}$/;

export function isIPv4(value: string): boolean {
  return V4.test(value);
}

export function isIPv6(value: string): boolean {
  const parts = value.split("%");
  if (parts.length > 2 || parts[1] === "") return false;
  let address = parts[0] ?? "";
  const lastColon = address.lastIndexOf(":");
  const tail = address.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (lastColon < 0 || !isIPv4(tail)) return false;
    address = `${address.slice(0, lastColon + 1)}0:0`;
  }
  const groups = (text: string) => (text === "" ? [] : text.split(":"));
  const halves = address.split("::");
  if (halves.length > 2) return false;
  if (halves.length === 1) {
    const all = groups(address);
    return all.length === 8 && all.every((group) => HEX.test(group));
  }
  const both = [...groups(halves[0] ?? ""), ...groups(halves[1] ?? "")];
  return both.length <= 7 && both.every((group) => HEX.test(group));
}

export function isIP(value: string): 0 | 4 | 6 {
  if (isIPv4(value)) return 4;
  if (isIPv6(value)) return 6;
  return 0;
}
