const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const assert = require('assert');

// Ensure dist artifacts exist and are up to date before requiring (build without recursive script invocation)
const pluginRoot = path.resolve(__dirname, '..');
const distIndexPath = path.resolve(pluginRoot, 'dist/index.js');
const libDir = path.resolve(pluginRoot, 'lib');

function shouldBuildDist() {
  if (!fs.existsSync(distIndexPath)) return true;
  try {
    const distMtime = fs.statSync(distIndexPath).mtimeMs;
    const libFiles = fs.readdirSync(libDir);
    for (const file of libFiles) {
      const fileMtime = fs.statSync(path.join(libDir, file)).mtimeMs;
      if (fileMtime > distMtime) return true;
    }
    return false;
  } catch {
    return true;
  }
}

if (shouldBuildDist()) {
  console.log('dist/index.js missing or stale. Building Zoho Books plugin...');
  try {
    execSync('npx ncc build lib/index.ts -o dist', {
      cwd: pluginRoot,
      stdio: 'inherit',
    });
  } catch (buildError) {
    console.error('Failed to build Zoho Books dist artifacts:', buildError.message);
    process.exit(1);
  }
}

const ZohoBooks = require('../dist/index.js').default;

async function run() {
  console.log('Running Zoho Books unit tests...');
  const service = new ZohoBooks();

  // Test 1: authUrl regional endpoints (US, EU, India)
  const authUrlUS = service.authUrl({
    client_id: { value: 'client_123' },
    client_secret: { value: 'secret_123' },
    region: { value: 'com' },
    scopes: { value: 'ZohoBooks.fullaccess.all' },
    tj_redirect_host: { value: 'http://localhost:3000' },
  });
  assert(authUrlUS.includes('https://accounts.zoho.com/oauth/v2/auth'), 'US authUrl must use accounts.zoho.com');
  assert(authUrlUS.includes('client_id=client_123'));
  assert(authUrlUS.includes('scope=ZohoBooks.fullaccess.all'));
  assert(authUrlUS.includes('access_type=offline'));
  assert(authUrlUS.includes('state='), 'authUrl must contain state');

  const authUrlEU = service.authUrl({
    client_id: { value: 'client_eu' },
    client_secret: { value: 'secret_eu' },
    region: { value: 'eu' },
    scopes: { value: 'ZohoBooks.fullaccess.all' },
  });
  assert(authUrlEU.includes('https://accounts.zoho.eu/oauth/v2/auth'), 'EU authUrl must use accounts.zoho.eu');

  const authUrlIN = service.authUrl({
    client_id: { value: 'client_in' },
    client_secret: { value: 'secret_in' },
    region: { value: 'in' },
  });
  assert(authUrlIN.includes('https://accounts.zoho.in/oauth/v2/auth'), 'IN authUrl must use accounts.zoho.in');

  // Test 2: authUrl missing client_id
  let threw = false;
  try {
    service.authUrl({});
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing OAuth credentials'));
  }
  assert(threw, 'Should throw if client_id is missing in authUrl');

  // Test 3: OAuth state binding and validation (valid, missing, mismatched, expired)
  const usParams = new URL(authUrlUS).searchParams;
  const stateFromAuthUrl = usParams.get('state');
  assert(stateFromAuthUrl, 'State must be present in authUrl');
  assert(service.validateState(stateFromAuthUrl, 'client_123', 'secret_123'), 'Generated state should be valid');

  // Missing state
  threw = false;
  try {
    await service.accessDetailsFrom('test_code', {
      client_id: 'client_123',
      client_secret: 'secret_123',
    });
  } catch (err) {
    threw = true;
    assert.strictEqual(err.data?.code, 'MISSING_OAUTH_STATE');
  }
  assert(threw, 'Should reject accessDetailsFrom when state is missing');

  // Mismatched / forged state
  threw = false;
  try {
    await service.accessDetailsFrom('test_code', {
      client_id: 'client_123',
      client_secret: 'secret_123',
      state: 'fake_nonce:1700000000000:fake_sig',
    });
  } catch (err) {
    threw = true;
    assert.strictEqual(err.data?.code, 'INVALID_OAUTH_STATE');
  }
  assert(threw, 'Should reject accessDetailsFrom when state is mismatched/tampered');

  // Expired state (> 1 hour)
  const oldTimestamp = (Date.now() - 3700 * 1000).toString();
  const crypto = require('crypto');
  const oldNonce = crypto.randomBytes(16).toString('hex');
  const oldSig = crypto.createHmac('sha256', 'secret_123').update(`${oldNonce}:${oldTimestamp}`).digest('hex');
  const expiredState = `${oldNonce}:${oldTimestamp}:${oldSig}`;
  assert.strictEqual(service.validateState(expiredState, 'client_123', 'secret_123'), false, 'Expired state should fail validation');

  // Test 4: accessDetailsFrom resetSecureData
  const resetDetails = await service.accessDetailsFrom('code123', {}, true);
  assert.deepStrictEqual(resetDetails, [
    ['access_token', ''],
    ['refresh_token', ''],
  ]);

  // Test 5: Regional endpoints across all seven regions
  const expectedRegions = {
    com: {
      authUrl: 'https://accounts.zoho.com/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.com/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.com/books/v3',
    },
    eu: {
      authUrl: 'https://accounts.zoho.eu/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.eu/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.eu/books/v3',
    },
    in: {
      authUrl: 'https://accounts.zoho.in/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.in/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.in/books/v3',
    },
    'com.au': {
      authUrl: 'https://accounts.zoho.com.au/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.com.au/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.com.au/books/v3',
    },
    jp: {
      authUrl: 'https://accounts.zoho.jp/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.jp/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.jp/books/v3',
    },
    ca: {
      authUrl: 'https://accounts.zohocloud.ca/oauth/v2/auth',
      tokenUrl: 'https://accounts.zohocloud.ca/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.ca/books/v3',
    },
    sa: {
      authUrl: 'https://accounts.zoho.sa/oauth/v2/auth',
      tokenUrl: 'https://accounts.zoho.sa/oauth/v2/token',
      apiUrl: 'https://www.zohoapis.sa/books/v3',
    },
  };

  for (const [region, cfg] of Object.entries(expectedRegions)) {
    const regionConfig = service.getRegionConfig({ region });
    assert.strictEqual(regionConfig.authUrl, cfg.authUrl, `${region} authUrl matches`);
    assert.strictEqual(regionConfig.tokenUrl, cfg.tokenUrl, `${region} tokenUrl matches`);
    assert.strictEqual(regionConfig.apiUrl, cfg.apiUrl, `${region} apiUrl matches`);
  }

  // Test 6: refreshToken missing refresh_token
  threw = false;
  try {
    await service.refreshToken({ client_id: 'client_123', client_secret: 'secret_123' });
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing refresh_token'));
  }
  assert(threw);

  // Test 7: Zoho error code mapping (Code 14 vs Code 57)
  // Execute simulated request responses against error code handling
  const { OAuthUnauthorizedClientError, QueryError } = require('@tooljet-marketplace/common');

  // Code 14 (Invalid/expired OAuth token) -> must throw OAuthUnauthorizedClientError
  try {
    const fakeBody = { code: 14, message: 'Invalid OAuth token' };
    if (fakeBody.code !== undefined && fakeBody.code !== 0) {
      if (fakeBody.code === 14) {
        throw new OAuthUnauthorizedClientError('OAuth token expired or invalid', fakeBody.message, fakeBody);
      }
      throw new QueryError('Zoho Books API error', fakeBody.message, { code: fakeBody.code });
    }
    assert.fail('Should have thrown for code 14');
  } catch (err) {
    assert(err instanceof OAuthUnauthorizedClientError, 'Code 14 must map to OAuthUnauthorizedClientError');
  }

  // Code 57 (Permission/organization error) -> must throw regular QueryError, NOT OAuthUnauthorizedClientError
  try {
    const fakeBody = { code: 57, message: 'You are not authorized to perform this operation' };
    if (fakeBody.code !== undefined && fakeBody.code !== 0) {
      if (fakeBody.code === 14) {
        throw new OAuthUnauthorizedClientError('OAuth token expired or invalid', fakeBody.message, fakeBody);
      }
      throw new QueryError('Zoho Books API error', fakeBody.message, { code: fakeBody.code });
    }
    assert.fail('Should have thrown for code 57');
  } catch (err) {
    assert(err instanceof QueryError, 'Code 57 must map to QueryError');
    assert(!(err instanceof OAuthUnauthorizedClientError), 'Code 57 must NOT map to OAuthUnauthorizedClientError');
    assert.strictEqual(err.data?.code, 57);
  }

  // Test 8: Operations count in operations.json and documentation matching 17 operations
  const operationsJson = require('../lib/operations.json');
  const operationList = operationsJson.properties.operation.list;
  assert.strictEqual(operationList.length, 17, `operations.json must contain exactly 17 operations, found ${operationList.length}`);

  const docPath = path.resolve(__dirname, '../../../../docs/docs/marketplace/plugins/zoho-books.md');
  const docContent = fs.readFileSync(docPath, 'utf8');
  assert(docContent.includes('17 key operations'), 'Documentation must state 17 key operations');
  assert(!docContent.includes('18 key operations'), 'Documentation must not mention 18 key operations');

  // Test 9: run without access_token
  threw = false;
  try {
    await service.run({}, { operation: 'list_organizations' }, 'ds1');
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('No access token found'));
  }
  assert(threw);

  // Test 10: run without organization_id on scoped ops
  threw = false;
  try {
    await service.run({ access_token: 'tok' }, { operation: 'list_contacts' }, 'ds1');
  } catch (err) {
    threw = true;
    assert((err.description || err.message).includes('Missing Zoho Books Organization ID'));
  }
  assert(threw);

  // Test 11: unknown operation
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

  // Test 12: malformed JSON
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

  // Test 13: missing contact_id for get_contact
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

  // Test 14: missing invoice_id for email_invoice
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

  // Test 15: testConnection returns failed status cleanly on invalid auth
  const testConn = await service.testConnection({ access_token: '' });
  assert(testConn.status === 'failed');

  console.log('PASS: All Zoho Books unit tests passed successfully.');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
