export class LoginPage {
  constructor(page) {
    this.page = page;
    this.operatorInput = page.getByPlaceholder('operator@sentinel.io');
    this.accessKeyInput = page.getByPlaceholder('••••••••••••');
    this.submitButton = page.getByRole('button', { name: /AUTHENTICATE/i });
    this.sessionError = page.locator('role=alert');
    this.systemAccessHeader = page.getByText('SYSTEM ACCESS');
  }

  async goto() {
    await this.page.goto('/login');
    await this.systemAccessHeader.waitFor({ state: 'visible' });
  }

  async login(email, password) {
    await this.operatorInput.fill(email);
    await this.accessKeyInput.fill(password);
    await this.submitButton.click();
  }
}
