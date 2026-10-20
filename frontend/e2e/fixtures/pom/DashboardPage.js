export class DashboardPage {
  constructor(page) {
    this.page = page;
    this.kpis = page.locator('.dashboard-kpis');
    this.panels = page.locator('.panel-base, .sentinel-panel');
    this.liveFeed = page.getByText(/Live Real-Time Security Feed/i);
    this.blockButtons = page.getByRole('button', { name: 'Block IP' });
    this.threatRows = page.locator('table tbody tr');
    this.statusBar = page.getByText(/Detection services/i);
    this.sidebar = page.locator('.sentinel-sidebar');
  }

  async goto() {
    await this.page.goto('/dashboard');
    await this.page.waitForURL('**/dashboard');
    await this.kpis.waitFor({ state: 'visible' });
  }

  async blockFirstIP() {
    await this.blockButtons.first().click();
  }
}
