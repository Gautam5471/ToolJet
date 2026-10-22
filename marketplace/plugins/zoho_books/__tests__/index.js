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

  // Test 3: OAuth state binding and validation (valid, missing, mismatched, expired, non-finite, future skew)
  const usParams = new URL(authUrlUS).searchParams;
  const stateFromAuthUrl = usParams.get('state');
  assert(stateFromAuthUrl, 'State must be present in authUrl');
  assert(stateFromAuthUrl.startsWith('zb:'), 'State must start with zb: prefix');
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
      state: 'zb:fake_nonce:1700000000000:fake_sig',
    });
  } catch (err) {
    threw = true;
    assert.strictEqual(err.data?.code, 'INVALID_OAUTH_STATE');
  }
  assert(threw, 'Should reject accessDetailsFrom when state is mismatched/tampered');

  // Prefix stripped state (e.g. without 'zb:')
  const strippedState = stateFromAuthUrl.replace(/^zb:/, '');
  assert.strictEqual(service.validateState(strippedState, 'client_123', 'secret_123'), false, 'Prefix-stripped state must be rejected');

  // Non-finite / NaN timestamp
  const crypto = require('crypto');
  const testNonce = crypto.randomBytes(16).toString('hex');
  const nanState = `zb:${testNonce}:not_a_number:somesig`;
  assert.strictEqual(service.validateState(nanState, 'client_123', 'secret_123'), false, 'NaN timestamp state must fail');

  // Expired state (> 1 hour)
  const oldTimestamp = (Date.now() - 3700 * 1000).toString();
  const oldSig = crypto.createHmac('sha256', 'secret_123').update(`${testNonce}:${oldTimestamp}`).digest('hex');
  const expiredState = `zb:${testNonce}:${oldTimestamp}:${oldSig}`;
  assert.strictEqual(service.validateState(expiredState, 'client_123', 'secret_123'), false, 'Expired state should fail validation');

  // Future timestamp beyond allowed clock skew (> 5 min in the future)
  const futureTimestamp = (Date.now() + 10 * 60 * 1000).toString();
  const futureSig = crypto.createHmac('sha256', 'secret_123').update(`${testNonce}:${futureTimestamp}`).digest('hex');
  const futureState = `zb:${testNonce}:${futureTimestamp}:${futureSig}`;
  assert.strictEqual(service.validateState(futureState, 'client_123', 'secret_123'), false, 'Future timestamp beyond skew window must fail');

  // Valid timestamp with allowable future clock skew (< 5 min in the future)
  const allowableFutureTs = (Date.now() + 2 * 60 * 1000).toString();
  const allowableFutureSig = crypto.createHmac('sha256', 'secret_123').update(`${testNonce}:${allowableFutureTs}`).digest('hex');
  const allowableFutureState = `zb:${testNonce}:${allowableFutureTs}:${allowableFutureSig}`;
  assert.strictEqual(service.validateState(allowableFutureState, 'client_123', 'secret_123'), true, 'Allowable future clock skew should pass');

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

  // Test 16: Removal of skip_state_validation bypass - state validation is mandatory
  threw = false;
  try {
    await service.accessDetailsFrom('test_code', {
      client_id: 'client_123',
      client_secret: 'secret_123',
      skip_state_validation: 'true',
    });
  } catch (err) {
    threw = true;
    assert.strictEqual(err.data?.code, 'MISSING_OAUTH_STATE', 'skip_state_validation must NOT bypass missing state');
  }
  assert(threw, 'Should reject even if skip_state_validation is passed');

  // Test 17: Frontend callback state matching simulation (per-flow lookup, cross-tab race isolation, binding checks)
  function simulatePerFlowAuthorizeCallback({
    code,
    state,
    storage, // Map or Object simulating window.localStorage
    currentOrgId = 'org_123',
    sourceWaiting = 'newSource',
  }) {
    let error = null;
    let authSuccess = false;
    let storedOAuthCode = null;
    let storedOAuthState = null;

    let flowData = null;
    if (state && storage[`oauth_flow_${state}`]) {
      try {
        flowData = JSON.parse(storage[`oauth_flow_${state}`]);
      } catch {
        flowData = null;
      }
    }

    const legacyProvider = storage['oauth_initiating_provider'];
    const legacyExpectedState = storage['oauth_expected_state'];

    const isZohoRegistered = flowData?.provider === 'zoho_books';
    const isZohoLegacy = legacyProvider === 'zoho_books';
    const isZohoPrefix = typeof state === 'string' && state.startsWith('zb:');
    const isZohoInitiated = isZohoRegistered || isZohoLegacy || isZohoPrefix;

    if (isZohoInitiated) {
      if (isZohoRegistered) {
        const ts = flowData.timestamp;
        const now = Date.now();
        if (typeof ts !== 'number' || !Number.isFinite(ts) || now - ts > 60 * 60 * 1000 || ts > now + 5 * 60 * 1000) {
          delete storage[`oauth_flow_${state}`];
          delete storage['OAuthCode'];
          delete storage['OAuthState'];
          return {
            authSuccess: false,
            error: 'OAuth state has expired or contains an invalid timestamp for Zoho Books authorization',
            storedOAuthCode: null,
            storedOAuthState: null,
          };
        }

        if (flowData.orgId && currentOrgId && flowData.orgId !== currentOrgId) {
          delete storage[`oauth_flow_${state}`];
          delete storage['OAuthCode'];
          delete storage['OAuthState'];
          return {
            authSuccess: false,
            error: 'OAuth organization mismatch for Zoho Books authorization',
            storedOAuthCode: null,
            storedOAuthState: null,
          };
        }

        if (flowData.sourceId && sourceWaiting && flowData.sourceId !== sourceWaiting) {
          delete storage[`oauth_flow_${state}`];
          delete storage['OAuthCode'];
          delete storage['OAuthState'];
          return {
            authSuccess: false,
            error: 'OAuth source mismatch for Zoho Books authorization',
            storedOAuthCode: null,
            storedOAuthState: null,
          };
        }

        // Consume the expected flow entry
        delete storage[`oauth_flow_${state}`];
      } else if (isZohoLegacy) {
        if (!state || !legacyExpectedState || state !== legacyExpectedState) {
          delete storage['OAuthCode'];
          delete storage['OAuthState'];
          return {
            authSuccess: false,
            error: 'Invalid or mismatched OAuth state parameter for Zoho Books authorization',
            storedOAuthCode: null,
            storedOAuthState: null,
          };
        }
        delete storage['oauth_expected_state'];
        delete storage['oauth_initiating_provider'];
      } else {
        delete storage['OAuthCode'];
        delete storage['OAuthState'];
        return {
          authSuccess: false,
          error: 'Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization',
          storedOAuthCode: null,
          storedOAuthState: null,
        };
      }
    }

    storedOAuthCode = code;
    storedOAuthState = state || null;
    authSuccess = true;
    return { authSuccess, error, storedOAuthCode, storedOAuthState };
  }

  // 17.1: Valid Zoho Books callback matching per-flow record
  const mockStorage1 = {
    [`oauth_flow_${stateFromAuthUrl}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'newSource',
      orgId: 'org_123',
      timestamp: Date.now(),
    }),
  };
  const validCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: stateFromAuthUrl,
    storage: mockStorage1,
  });
  assert(validCallback.authSuccess, 'Valid Zoho Books state should succeed');
  assert.strictEqual(validCallback.storedOAuthCode, 'code_abc');
  assert.strictEqual(mockStorage1[`oauth_flow_${stateFromAuthUrl}`], undefined, 'Flow data must be consumed after success');

  // 17.2: Missing state on Zoho Books callback with legacy expectation
  const mockStorage2 = {
    oauth_initiating_provider: 'zoho_books',
    oauth_expected_state: stateFromAuthUrl,
  };
  const missingCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: undefined,
    storage: mockStorage2,
  });
  assert(!missingCallback.authSuccess, 'Missing state should be rejected');
  assert(missingCallback.error.includes('Invalid or mismatched OAuth state parameter'));

  // 17.3: Mismatched state on Zoho Books callback (frontend rejects unknown flow record)
  const mockStorage3 = {
    [`oauth_flow_${stateFromAuthUrl}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'newSource',
      orgId: 'org_123',
      timestamp: Date.now(),
    }),
  };
  const mismatchedCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: 'zb:completely_different_state:12345:signature',
    storage: mockStorage3,
  });
  assert(!mismatchedCallback.authSuccess, 'Mismatched callback should be rejected by frontend');
  assert(mismatchedCallback.error.includes('Invalid, missing, or already consumed'));
  assert.strictEqual(mismatchedCallback.storedOAuthCode, null);

  // Verify backend plugin also rejects mismatched state
  let backendThrew = false;
  try {
    await service.accessDetailsFrom('code_abc', {
      client_id: 'client_123',
      client_secret: 'secret_123',
      state: 'zb:completely_different_state:12345:signature',
    });
  } catch (err) {
    backendThrew = true;
    assert.strictEqual(err.data?.code, 'INVALID_OAUTH_STATE');
  }
  assert(backendThrew, 'Backend must reject mismatched state');

  // 17.4: Expired state on Zoho Books callback (> 1 hour)
  const mockStorage4 = {
    [`oauth_flow_${stateFromAuthUrl}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'newSource',
      orgId: 'org_123',
      timestamp: Date.now() - 3700 * 1000,
    }),
  };
  const expiredCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: stateFromAuthUrl,
    storage: mockStorage4,
  });
  assert(!expiredCallback.authSuccess, 'Expired flow state should be rejected');
  assert(expiredCallback.error.includes('expired or contains an invalid timestamp'));
  assert.strictEqual(mockStorage4[`oauth_flow_${stateFromAuthUrl}`], undefined, 'Expired flow data must be cleaned up');

  // 17.5: Organization mismatch check
  const mockStorageOrg = {
    [`oauth_flow_${stateFromAuthUrl}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'newSource',
      orgId: 'org_OTHER',
      timestamp: Date.now(),
    }),
  };
  const orgMismatchCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: stateFromAuthUrl,
    storage: mockStorageOrg,
    currentOrgId: 'org_CURRENT',
  });
  assert(!orgMismatchCallback.authSuccess, 'Organization mismatch should be rejected');
  assert(orgMismatchCallback.error.includes('organization mismatch'));

  // 17.6: Source mismatch check
  const mockStorageSource = {
    [`oauth_flow_${stateFromAuthUrl}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'ds_EXPECTED',
      orgId: 'org_123',
      timestamp: Date.now(),
    }),
  };
  const sourceMismatchCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: stateFromAuthUrl,
    storage: mockStorageSource,
    sourceWaiting: 'ds_ACTUAL',
  });
  assert(!sourceMismatchCallback.authSuccess, 'Source mismatch should be rejected');
  assert(sourceMismatchCallback.error.includes('source mismatch'));

  // 17.7: Replayed state (already consumed, so oauth_flow_<state> is deleted)
  const mockStorage5 = {}; // consumed
  const replayedCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_abc',
    state: stateFromAuthUrl,
    storage: mockStorage5,
  });
  assert(!replayedCallback.authSuccess, 'Replayed Zoho Books state callback must be rejected');
  assert(replayedCallback.error.includes('Invalid, missing, or already consumed'));
  assert.strictEqual(replayedCallback.storedOAuthCode, null);

  // 17.6: Concurrent Zoho Books flows in separate tabs (No cross-flow cleanup deletion)
  const stateFlowA = 'state_tab_A';
  const stateFlowB = 'state_tab_B';
  const sharedStorage = {
    [`oauth_flow_${stateFlowA}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'ds_A',
      timestamp: Date.now(),
    }),
    [`oauth_flow_${stateFlowB}`]: JSON.stringify({
      provider: 'zoho_books',
      sourceId: 'ds_B',
      timestamp: Date.now(),
    }),
  };

  // Flow A completes and consumes its own flow key
  const callbackA = simulatePerFlowAuthorizeCallback({
    code: 'code_A',
    state: stateFlowA,
    storage: sharedStorage,
    sourceWaiting: 'ds_A',
  });
  assert(callbackA.authSuccess, 'Flow A must succeed');
  assert.strictEqual(sharedStorage[`oauth_flow_${stateFlowA}`], undefined, 'Flow A key must be deleted');
  assert(sharedStorage[`oauth_flow_${stateFlowB}`] !== undefined, 'Flow B key must NOT be deleted by Flow A completion');

  // Flow B completes subsequently without interference
  const callbackB = simulatePerFlowAuthorizeCallback({
    code: 'code_B',
    state: stateFlowB,
    storage: sharedStorage,
    sourceWaiting: 'ds_B',
  });
  assert(callbackB.authSuccess, 'Flow B must succeed independently');
  assert.strictEqual(sharedStorage[`oauth_flow_${stateFlowB}`], undefined, 'Flow B key must now be deleted');

  // 17.7: Unrelated OAuth provider (e.g. googlesheets, slack) should NOT be blocked
  const mockStorageOther = {};
  const otherProviderCallback = simulatePerFlowAuthorizeCallback({
    code: 'code_slack',
    state: undefined,
    storage: mockStorageOther,
  });
  assert(otherProviderCallback.authSuccess, 'Other OAuth providers without state must succeed');
  assert.strictEqual(otherProviderCallback.storedOAuthCode, 'code_slack');

  console.log('PASS: All Zoho Books unit tests passed successfully.');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
