'use strict'
/**
 * Toolchain guard (CI-003). authBrowser.test.js loads puppeteer-core (an ES module) through Node's native
 * createRequire, which needs Node's own require(esm). Jest 30.5.x intercepts that call and throws
 * ERR_REQUIRE_ESM unless --experimental-vm-modules is set; a semver-compatible `npm audit fix` moved the lockfile
 * from Jest 30.4.2 to 30.5.2 and failed the "Backend (MongoDB-backed suites)" job on PR #2.
 *
 * authBrowser only runs in that separate job (it needs MongoDB, a browser and the frontend), so this check runs
 * in the default job and fails fast if a toolchain change breaks the same load path again. No browser is started.
 */
test('puppeteer-core loads through native createRequire inside Jest', () => {
  const load = () => process.getBuiltinModule('module').createRequire(__filename)('puppeteer-core')
  expect(load).not.toThrow()
  expect(typeof load().launch).toBe('function')
})
