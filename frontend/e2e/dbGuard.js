// Pure guard, kept free of backend imports so unit tests can load it without backend/node_modules.
export function validateTestDatabaseName(mongoUri) {
  const dbName = (mongoUri || '').split('/').pop().split('?')[0];
  if (!dbName || !dbName.toLowerCase().includes('test')) {
    throw new Error(`CRITICAL SAFETY ERROR: Test database "${dbName}" must contain "test"! Refusing to operate on non-test database.`);
  }
  return dbName;
}
