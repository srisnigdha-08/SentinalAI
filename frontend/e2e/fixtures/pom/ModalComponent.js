export class ModalComponent {
  constructor(page) {
    this.page = page;
    this.dialog = page.getByRole('dialog');
    this.closeButton = page.getByRole('button', { name: '✕' });
    this.cancelButton = this.dialog.getByRole('button', { name: /Cancel/i });
    this.applyContainmentButton = this.dialog.getByRole('button', { name: /Apply Containment Policy/i });
    this.updateTriageButton = this.dialog.getByRole('button', { name: /Update Incident Triage/i });
    this.durationSelect = this.dialog.getByLabel('Containment Duration (TTL)');
    this.reasonInput = this.dialog.getByLabel('Operator Justification / Notes');
    this.triageStatusSelect = this.dialog.getByLabel('Workflow Incident Status');
    this.triageNotesTextarea = this.dialog.getByLabel('Analyst Investigation Notes & Dossier Annotations');
  }

  async waitForOpen() {
    await this.dialog.waitFor({ state: 'visible' });
  }

  async waitForClosed() {
    await this.dialog.waitFor({ state: 'hidden' });
  }

  async close() {
    await this.closeButton.click();
    await this.waitForClosed();
  }

  async cancel() {
    await this.cancelButton.click();
    await this.waitForClosed();
  }
}
