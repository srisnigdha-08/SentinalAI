export class ChangePasswordPage {
  constructor(page) {
    this.page = page;
    this.currentPasswordInput = page.getByLabel('Current Password', { exact: true });
    this.newPasswordInput = page.getByLabel('New Password', { exact: true });
    this.confirmPasswordInput = page.getByLabel('Confirm New Password', { exact: true });
    this.submitButton = page.getByRole('button', { name: /UPDATE PASSWORD/i });
    this.errorAlert = page.locator('role=alert');
    this.heading = page.getByText('PASSWORD CHANGE REQUIRED');
  }

  async goto() {
    await this.page.goto('/change-password');
    await this.heading.waitFor({ state: 'visible' });
  }

  async changePassword(currentPassword, newPassword, confirmPassword) {
    if (currentPassword !== undefined) await this.currentPasswordInput.fill(currentPassword);
    if (newPassword !== undefined) await this.newPasswordInput.fill(newPassword);
    if (confirmPassword !== undefined) await this.confirmPasswordInput.fill(confirmPassword);
    await this.submitButton.click();
  }
}
