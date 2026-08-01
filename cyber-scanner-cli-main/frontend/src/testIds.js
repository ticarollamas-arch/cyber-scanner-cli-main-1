export const TID = {
  landing: {
    ctaGetStarted: 'landing-cta-get-started',
    ctaLearnMore: 'landing-cta-learn-more',
    login: 'landing-login',
  },
  auth: {
    emailInput: 'auth-email-input',
    passwordInput: 'auth-password-input',
    nameInput: 'auth-name-input',
    submitBtn: 'auth-submit-btn',
    toggleMode: 'auth-toggle-mode',
    logoutBtn: 'auth-logout-btn',
  },
  dashboard: {
    newScanBtn: 'dashboard-new-scan-btn',
    scanCard: (id) => `dashboard-scan-card-${id}`,
    statsTotal: 'dashboard-stats-total',
    statsCompleted: 'dashboard-stats-completed',
    statsCritical: 'dashboard-stats-critical',
  },
  upload: {
    projectNameInput: 'upload-project-name-input',
    dropzone: 'upload-dropzone',
    fileInput: 'upload-file-input',
    submitBtn: 'upload-submit-btn',
  },
  scan: {
    tabOverview: 'scan-tab-overview',
    tabVulns: 'scan-tab-vulns',
    tabTerminal: 'scan-tab-terminal',
    tabReport: 'scan-tab-report',
    vulnRow: (id) => `scan-vuln-row-${id}`,
    downloadPdf: 'scan-download-pdf',
    downloadMd: 'scan-download-md',
  },
  terminal: {
    container: 'terminal-container',
    input: 'terminal-input',
    runBtn: 'terminal-run-btn',
    presetBtn: (n) => `terminal-preset-${n}`,
  },
};
