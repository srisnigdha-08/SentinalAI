export class UserManagementPage {
  constructor(page) {
    this.page = page;
    this.provisionToggle = page.getByRole('button', { name: /\+ Provision Operator|Cancel/i });
    this.nameInput = page.getByLabel('Full name');
    this.emailInput = page.getByLabel('Email');
    this.passwordInput = page.getByLabel('Initial password');
    this.departmentInput = page.getByLabel('Department');
    this.roleSelect = page.getByLabel('Role');
    this.submitProvisionButton = page.getByRole('button', { name: 'Provision account' });
    this.userTable = page.locator('.sentinel-table-scroll table');
    this.userRows = page.locator('.sentinel-table-scroll table tbody tr');
    this.deleteButtons = page.getByRole('button', { name: 'Delete' });
  }

  async goto() {
    await this.page.goto('/dashboard/users');
    await this.page.waitForURL('**/dashboard/users');
    await this.provisionToggle.waitFor({ state: 'visible' });
  }

  async openProvisionForm() {
    await this.provisionToggle.click();
    await this.nameInput.waitFor({ state: 'visible' });
  }

  async provisionUser({ name, email, password, department = 'SOC', role = 'viewer' }) {
    await this.openProvisionForm();
    await this.nameInput.fill(name);
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.departmentInput.fill(department);
    await this.roleSelect.selectOption(role);
    await this.submitProvisionButton.click();
  }
}
