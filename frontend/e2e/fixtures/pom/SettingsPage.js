export class SettingsPage {
  constructor(page) {
    this.page = page;
    this.autoBlockToggle = page.getByRole('button', { name: /ACTIVE \/ ON|DISABLED \/ OFF/i });
    this.ipInput = page.getByPlaceholder('e.g. 185.220.101.47');
    this.reasonInput = page.getByPlaceholder('e.g. Manual block of scanner IP');
    this.enforceBlockButton = page.getByRole('button', { name: 'Enforce IP Block' });
    this.unblockButtons = page.getByRole('button', { name: 'Unblock IP' });
    this.auditPanel = page.getByText(/Security & Compliance Audit Trail/i);
    this.blocklistTable = page.locator('.sentinel-table-scroll table');
  }

  async goto() {
    await this.page.goto('/settings');
    await this.page.waitForURL('**/settings');
    await this.ipInput.waitFor({ state: 'visible' });
  }

  async fillManualBlock(ip, reason = 'Test containment policy') {
    await this.ipInput.fill(ip);
    await this.reasonInput.fill(reason);
    await this.enforceBlockButton.click();
  }
}
