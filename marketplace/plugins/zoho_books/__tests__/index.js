const assert = require('assert');
const ZohoBooks = require('../dist/index.js').default;

async function run() {
  console.log('Running Zoho Books unit tests...');
  const service = new ZohoBooks();

  // Test 1: authUrl
  const authUrlUS = service.authUrl({
    client_id: { value: 'client_123' },
    region: { value: 'com' },
    scopes: { value: 'ZohoBooks.fullaccess.all' },
    tj_redirect_host: { value: 'http://localhost:3000' },
  });
  assert(authUrlUS.includes('https://accounts.zoho.com/oauth/v2/auth'));
  assert(authUrlUS.includes('client_id=client_123'));
  assert(authUrlUS.includes('scope=ZohoBooks.fullaccess.all'));
  assert(authUrlUS.includes('access_type=offline'));

  const authUrlEU = service.authUrl({
    client_id: { value: 'client_eu' },
    region: { value: 'eu' },
    scopes: { value: 'ZohoBooks.fullaccess.all' },
  });
  assert(authUrlEU.includes('https://accounts.zoho.eu/oauth/v2/auth'));

  const authUrlIN = service.authUrl({
    client_id: { value: 'client_in' },
    region: { value: 'in' },
  });
  assert(authUrlIN.includes('https://accounts.zoho.in/oauth/v2/auth'));

  // Test 2: authUrl missing client_id
  let threw = false;
  try {
    service.authUrl({});
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing OAuth credentials'));
  }
  assert(threw);

  // Test 3: accessDetailsFrom resetSecureData
  const resetDetails = await service.accessDetailsFrom('code123', {}, true);
  assert.deepStrictEqual(resetDetails, [
    ['access_token', ''],
    ['refresh_token', ''],
  ]);

  // Test 4: refreshToken missing refresh_token
  threw = false;
  try {
    await service.refreshToken({ client_id: 'client_123', client_secret: 'secret_123' });
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing refresh_token'));
  }
  assert(threw);

  // Test 5: run without access_token
  threw = false;
  try {
    await service.run({}, { operation: 'list_organizations' }, 'ds1');
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('No access token found'));
  }
  assert(threw);

  // Test 6: run without organization_id on scoped ops
  threw = false;
  try {
    await service.run({ access_token: 'tok' }, { operation: 'list_contacts' }, 'ds1');
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing Zoho Books Organization ID'));
  }
  assert(threw);

  // Test 7: unknown operation
  threw = false;
  try {
    await service.run(
      { access_token: 'tok', organization_id: { value: '701' } },
      { operation: 'unknown_op' },
      'ds1'
    );
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Unknown operation'));
  }
  assert(threw);

  // Test 8: malformed JSON
  threw = false;
  try {
    await service.run(
      { access_token: 'tok', organization_id: { value: '701' } },
      { operation: 'create_contact', contact_data: '{' },
      'ds1'
    );
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('invalid JSON'));
  }
  assert(threw);

  // Test 9: missing contact_id for get_contact
  threw = false;
  try {
    await service.run(
      { access_token: 'tok', organization_id: { value: '701' } },
      { operation: 'get_contact' },
      'ds1'
    );
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Contact ID is required'));
  }
  assert(threw);

  // Test 10: missing invoice_id for email_invoice
  threw = false;
  try {
    await service.run(
      { access_token: 'tok', organization_id: { value: '701' } },
      { operation: 'email_invoice' },
      'ds1'
    );
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Invoice ID is required'));
  }
  assert(threw);

  // Test 11: testConnection returns failed status cleanly on invalid auth
  const testConn = await service.testConnection({ access_token: '' });
  assert(testConn.status === 'failed');

  console.log('PASS: All 11 unit tests passed successfully.');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
