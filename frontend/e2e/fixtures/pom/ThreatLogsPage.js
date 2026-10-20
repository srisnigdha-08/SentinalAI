export class ThreatLogsPage {
  constructor(page) {
    this.page = page;
    this.searchInput = page.getByPlaceholder('Search IP, type...');
    this.severitySelect = page.locator('select').first();
    this.typeSelect = page.locator('select').nth(1);
    this.exportCsvButton = page.getByRole('button', { name: 'Export CSV' });
    this.table = page.locator('.sentinel-table-scroll table');
    this.rows = page.locator('.sentinel-table-scroll table tbody tr');
    this.triageButtons = page.getByRole('button', { name: 'Triage' });
    this.blockButtons = page.getByRole('button', { name: 'Block' });
    this.severityBadges = page.locator('.sentinel-badge, [style*="border-radius: 2px"]');
  }

  async goto() {
    await this.page.goto('/dashboard/threats');
    await this.page.waitForURL('**/dashboard/threats');
    await this.searchInput.waitFor({ state: 'visible' });
  }

  async search(query) {
    await this.searchInput.fill(query);
    await this.searchInput.press('Enter');
  }

  async filterSeverity(severity) {
    await this.severitySelect.selectOption(severity);
  }

  async openTriageModal(rowIndex = 0) {
    await this.triageButtons.nth(rowIndex).click();
  }

  async openContainmentModal(rowIndex = 0) {
    await this.blockButtons.nth(rowIndex).click();
  }
}
