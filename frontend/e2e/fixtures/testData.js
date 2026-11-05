// TEST-010: addresses for threats a spec creates. The old generator (time-based, modulo 200) could hand two tests,
// browsers or repeats the same address in one run, so "appears exactly once" saw an earlier test's threat.
// Deterministic instead: 198.18.0.0/15 (benchmarking range, never seeded) with
//   third octet  = project block (40 per project) + the calling test's fixed slot (1-39, unique per spec file),
//   fourth octet = 10 + repeat (20 each) + retry (5 each) + n (0-4, several addresses within one test).
// globalSetup clears threats and alerts at the start of every run, so runs never see each other's data.
const PROJECTS = ['chromium', 'firefox', 'webkit', 'Mobile (Pixel 5)', 'Tablet (iPad)'];

export function testIp(testInfo, slot, n = 0) {
  const project = PROJECTS.indexOf(testInfo.project.name);
  if (project < 0) throw new Error(`testIp: unknown project ${testInfo.project.name}`);
  if (!Number.isInteger(slot) || slot < 1 || slot > 39) throw new Error(`testIp: slot ${slot} out of 1-39`);
  if (!Number.isInteger(n) || n < 0 || n > 4) throw new Error(`testIp: n ${n} out of 0-4`);
  const host = 10 + testInfo.repeatEachIndex * 20 + testInfo.retry * 5 + n;
  if (host > 254) throw new Error('testIp: too many repeats for one /24 (repeat-each <= 12)');
  return `198.18.${project * 40 + slot}.${host}`;
}

/**
 * An address in a /24 no other (project, repeat, retry) uses, for tests that match the viewer's redacted form
 * (a.b.c.xxx): 198.19.<project * 50 + repeat * 4 + retry>.10.
 */
export function testSubnetIp(testInfo) {
  const project = PROJECTS.indexOf(testInfo.project.name);
  if (project < 0) throw new Error(`testSubnetIp: unknown project ${testInfo.project.name}`);
  if (testInfo.repeatEachIndex > 11 || testInfo.retry > 3) throw new Error('testSubnetIp: repeat-each <= 12, retries <= 3');
  return `198.19.${project * 50 + testInfo.repeatEachIndex * 4 + testInfo.retry}.10`;
}
