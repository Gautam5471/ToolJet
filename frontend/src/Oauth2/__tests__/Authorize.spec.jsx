import React from 'react';
import { render, screen, waitFor } from '@/test/test-utils';
import { Authorize } from '@/Oauth2';
import { datasourceService } from '@/_services';

jest.mock('@/_services', () => ({
  datasourceService: {
    setOauth2Token: jest.fn(),
  },
}));

describe('Authorize OAuth2 callback component', () => {
  let originalClose;

  beforeEach(() => {
    jest.clearAllMocks();
    localStorage.clear();
    originalClose = window.close;
    window.close = jest.fn();
  });

  afterEach(() => {
    window.close = originalClose;
  });

  test('rejects callback when state belongs to Zoho Books format but no initiating flow record exists (mismatched/missing/replayed)', async () => {
    // Zoho-format state (zb:nonce:timestamp:sig) with no matching flow record in localStorage
    const mismatchedState = 'zb:fake_nonce:1700000000000:fake_sig';
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    render(<Authorize />, { route: `/oauth2/authorize?code=test_code&state=${mismatchedState}` });

    await waitFor(() => {
      expect(
        screen.getByText('Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization')
      ).toBeInTheDocument();
    });

    // Ensures neither code nor state is saved to localStorage on error
    expect(localStorage.getItem('OAuthCode')).toBeNull();
    expect(localStorage.getItem('OAuthState')).toBeNull();
    expect(datasourceService.setOauth2Token).not.toHaveBeenCalled();
  });

  test('rejects callback when Zoho Books flow record has expired (> 1 hour)', async () => {
    const expiredState = 'zb:expired_nonce:1700000000000:expired_sig';
    localStorage.setItem(
      `oauth_flow_${expiredState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        timestamp: Date.now() - 3700 * 1000,
      })
    );

    render(<Authorize />, { route: `/oauth2/authorize?code=test_code&state=${expiredState}` });

    await waitFor(() => {
      expect(screen.getByText(/OAuth state has expired or contains an invalid timestamp/i)).toBeInTheDocument();
    });

    // Record is cleaned up on expiration
    expect(localStorage.getItem(`oauth_flow_${expiredState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBeNull();
    expect(datasourceService.setOauth2Token).not.toHaveBeenCalled();
  });

  test('rejects callback when timestamp is NaN, non-finite, or beyond future clock skew', async () => {
    const invalidTsState = 'zb:invalid_ts_nonce:not_a_number:sig';
    localStorage.setItem(
      `oauth_flow_${invalidTsState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        timestamp: 'invalid_string_timestamp',
      })
    );

    render(<Authorize />, { route: `/oauth2/authorize?code=test_code&state=${invalidTsState}` });

    await waitFor(() => {
      expect(screen.getByText(/OAuth state has expired or contains an invalid timestamp/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem(`oauth_flow_${invalidTsState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBeNull();
  });

  test('rejects callback when organizationId in flowData mismatches current organization (stale or mismatched)', async () => {
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        orgId: 'org_A',
        timestamp: Date.now(),
      })
    );
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');
    document.cookie = 'orgIdForOauth=org_B';

    render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(screen.getByText(/OAuth organization mismatch for Zoho Books authorization/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBeNull();
  });

  test('rejects callback when orgIdForOauth cookie is missing', async () => {
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        orgId: 'org_A',
        timestamp: Date.now(),
      })
    );
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');
    // Clear cookie so orgIdForOauth is missing
    document.cookie = 'orgIdForOauth=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';

    render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(screen.getByText(/OAuth organization mismatch for Zoho Books authorization/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBeNull();
  });

  test('rejects callback when sourceId in flowData mismatches sourceWaitingForOAuth', async () => {
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'ds_EXPECTED',
        orgId: 'org_TEST',
        timestamp: Date.now(),
      })
    );
    document.cookie = 'orgIdForOauth=org_TEST';
    localStorage.setItem('sourceWaitingForOAuth', 'ds_DIFFERENT');

    render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(screen.getByText(/OAuth source mismatch for Zoho Books authorization/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBeNull();
  });

  test('successfully validates and consumes state for a valid Zoho Books flow on existing source', async () => {
    datasourceService.setOauth2Token.mockResolvedValueOnce({ status: 'ok' });
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'ds_123',
        orgId: 'org_TEST',
        timestamp: Date.now(),
      })
    );
    document.cookie = 'orgIdForOauth=org_TEST';
    localStorage.setItem('sourceWaitingForOAuth', 'ds_123');

    render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(datasourceService.setOauth2Token).toHaveBeenCalledWith(
        'ds_123',
        { code: 'valid_code_123', state: validState },
        'org_TEST'
      );
    });

    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
  });

  test('successfully validates and consumes state for a valid Zoho Books flow (newSource)', async () => {
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        orgId: 'org_TEST',
        timestamp: Date.now(),
      })
    );
    document.cookie = 'orgIdForOauth=org_TEST';
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(screen.getByText(/Authorisation successful/i)).toBeInTheDocument();
    });

    // Flow record must be consumed immediately to prevent replay
    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
    expect(localStorage.getItem('OAuthCode')).toBe('valid_code_123');
    expect(localStorage.getItem('OAuthState')).toBe(validState);
  });

  test('allows unrelated OAuth providers to authorize without state rejection', async () => {
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    render(<Authorize />, { route: '/oauth2/authorize?code=slack_code_123' });

    await waitFor(() => {
      expect(screen.getByText(/Authorisation successful/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem('OAuthCode')).toBe('slack_code_123');
  });

  test('preserves pending unrelated OAuthCode when an invalid Zoho callback is rejected', async () => {
    // Simulate Slack flow actively storing its OAuthCode and OAuthState
    localStorage.setItem('OAuthCode', 'slack_auth_code_active');
    localStorage.setItem('OAuthState', 'slack_active_state');
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    // A rejected Zoho callback arrives with an unverified Zoho state
    const rejectedZohoState = 'zb:fake_zoho_nonce:1700000000000:fake_sig';
    render(<Authorize />, { route: `/oauth2/authorize?code=bad_code&state=${rejectedZohoState}` });

    await waitFor(() => {
      expect(
        screen.getByText('Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization')
      ).toBeInTheDocument();
    });

    // Unrelated Slack OAuthCode and OAuthState MUST remain intact
    expect(localStorage.getItem('OAuthCode')).toBe('slack_auth_code_active');
    expect(localStorage.getItem('OAuthState')).toBe('slack_active_state');
  });

  test('cleans up stale OAuthCode/OAuthState when the rejected callback matches the stored state', async () => {
    const rejectedZohoState = 'zb:fake_zoho_nonce:1700000000000:fake_sig';
    localStorage.setItem('OAuthCode', 'stale_zoho_code');
    localStorage.setItem('OAuthState', rejectedZohoState);
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    render(<Authorize />, { route: `/oauth2/authorize?code=bad_code&state=${rejectedZohoState}` });

    await waitFor(() => {
      expect(
        screen.getByText('Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization')
      ).toBeInTheDocument();
    });

    // When the state matches, it MUST be purged to prevent stale submission
    expect(localStorage.getItem('OAuthCode')).toBeNull();
    expect(localStorage.getItem('OAuthState')).toBeNull();
  });

  test('operates correctly when Web Locks API is unavailable in browser environment', async () => {
    const originalLocks = navigator.locks;
    delete navigator.locks; // Simulate unsupported environment

    try {
      const validState = 'zb:valid_nonce_nolocks:1700000000000:valid_sig';
      localStorage.setItem(
        `oauth_flow_${validState}`,
        JSON.stringify({
          provider: 'zoho_books',
          sourceId: 'newSource',
          orgId: 'org_TEST',
          timestamp: Date.now(),
        })
      );
      document.cookie = 'orgIdForOauth=org_TEST';
      localStorage.setItem('sourceWaitingForOAuth', 'newSource');

      render(<Authorize />, { route: `/oauth2/authorize?code=code_nolocks&state=${validState}` });

      await waitFor(() => {
        expect(screen.getByText(/Authorisation successful/i)).toBeInTheDocument();
      });

      expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
      expect(localStorage.getItem('OAuthCode')).toBe('code_nolocks');
    } finally {
      navigator.locks = originalLocks;
    }
  });

  test('replayed callback is rejected once state is already consumed', async () => {
    const validState = 'zb:valid_nonce:1700000000000:valid_sig';
    localStorage.setItem(
      `oauth_flow_${validState}`,
      JSON.stringify({
        provider: 'zoho_books',
        sourceId: 'newSource',
        orgId: 'org_TEST',
        timestamp: Date.now(),
      })
    );
    document.cookie = 'orgIdForOauth=org_TEST';
    localStorage.setItem('sourceWaitingForOAuth', 'newSource');

    // First run consumes the record
    const { unmount } = render(<Authorize />, { route: `/oauth2/authorize?code=valid_code_123&state=${validState}` });

    await waitFor(() => {
      expect(screen.getByText(/Authorisation successful/i)).toBeInTheDocument();
    });

    expect(localStorage.getItem(`oauth_flow_${validState}`)).toBeNull();
    unmount();
    localStorage.removeItem('OAuthCode');
    localStorage.removeItem('OAuthState');

    // Second run with the same state (replay attempt)
    render(<Authorize />, { route: `/oauth2/authorize?code=replayed_code&state=${validState}` });

    await waitFor(() => {
      expect(
        screen.getByText('Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization')
      ).toBeInTheDocument();
    });

    expect(localStorage.getItem('OAuthCode')).toBeNull();
    expect(datasourceService.setOauth2Token).not.toHaveBeenCalled();
  });
});
