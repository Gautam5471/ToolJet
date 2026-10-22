import React from 'react';
import queryString from 'query-string';
import { datasourceService } from '@/_services';
import { TJLoader } from '@/_ui/TJLoader/TJLoader';
import { withTranslation } from 'react-i18next';
import { getCookie } from '@/_helpers/cookie';
import { withRouter } from '@/_hoc/withRouter';
import VerifiedShield from '@/_ui/Icon/solidIcons/VerifiedShield';
import WarningOctagon from '@/_ui/Icon/solidIcons/WarningOctagon';
class AuthorizeComponent extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      isLoading: true,
    };
  }

  componentDidMount() {
    const props = this.props;
    const query = props.location.search;
    const params = queryString.parse(query);
    const code = params.code;
    const state = params.state;
    const details = { code, ...(state ? { state } : {}) };

    const lockKey = state ? `tj_oauth_lock_${state}` : 'tj_oauth_generic_lock';

    const processAuth = async () => {
      const sourceId = localStorage.getItem('sourceWaitingForOAuth');
      const current_organization_id = getCookie('orgIdForOauth');

      // Check if this callback corresponds to a registered OAuth flow (e.g., Zoho Books)
      let flowData = null;
      let rawFlow = null;
      if (state) {
        try {
          rawFlow = localStorage.getItem(`oauth_flow_${state}`);
          if (rawFlow) {
            flowData = JSON.parse(rawFlow);
          }
        } catch {
          // parsing error
        }
      }

      // Check legacy initiating keys
      const legacyProvider = localStorage.getItem('oauth_initiating_provider');
      const legacyExpectedState = localStorage.getItem('oauth_expected_state');

      // Trustworthy identification of Zoho Books:
      // 1. Registered flowData identifies provider as zoho_books
      // 2. Legacy provider key identifies zoho_books
      // 3. Callback state begins with 'zb:' prefix
      // 4. Initiating sourceWaitingForOAuth matches a registered Zoho flow
      const isZohoRegistered = flowData?.provider === 'zoho_books';
      const isZohoLegacy = legacyProvider === 'zoho_books';
      const isZohoPrefix = typeof state === 'string' && state.startsWith('zb:');
      const isZohoInitiated = isZohoRegistered || isZohoLegacy || isZohoPrefix;

      if (isZohoInitiated) {
        // Enforce Zoho-specific validation
        if (isZohoRegistered) {
          // Strictly validate numeric timestamp with internally consistent window (1 hour past, 5 min future skew)
          const ts = flowData.timestamp;
          const now = Date.now();
          if (typeof ts !== 'number' || !Number.isFinite(ts) || now - ts > 60 * 60 * 1000 || ts > now + 5 * 60 * 1000) {
            this.handleAuthFailure(
              'OAuth state has expired or contains an invalid timestamp for Zoho Books authorization',
              state
            );
            return;
          }

          // Strictly validate organization binding (mandatory for Zoho Books flows)
          if (!flowData.orgId || !current_organization_id || flowData.orgId !== current_organization_id) {
            this.handleAuthFailure('OAuth organization mismatch for Zoho Books authorization', state);
            return;
          }

          // Strictly validate sourceId binding (mandatory for Zoho Books flows)
          if (!flowData.sourceId || !sourceId || flowData.sourceId !== sourceId) {
            this.handleAuthFailure('OAuth source mismatch for Zoho Books authorization', state);
            return;
          }

          // Atomically consumed within lock
          localStorage.removeItem(`oauth_flow_${state}`);
        } else if (isZohoLegacy) {
          if (!state || !legacyExpectedState || state !== legacyExpectedState) {
            this.handleAuthFailure('Invalid or mismatched OAuth state parameter for Zoho Books authorization', state);
            return;
          }
          localStorage.removeItem('oauth_expected_state');
          localStorage.removeItem('oauth_initiating_provider');
        } else {
          // Stated was formatted as Zoho (or attempted Zoho flow), but no valid, unconsumed transaction record exists
          this.handleAuthFailure(
            'Invalid, missing, or already consumed OAuth state parameter for Zoho Books authorization',
            state
          );
          return;
        }
      }

      if (sourceId !== 'newSource') {
        datasourceService
          .setOauth2Token(sourceId, details, current_organization_id)
          .then(() => {
            this.setState({
              isLoading: false,
              authSuccess: true,
            });
          })
          .catch((error) => {
            this.handleAuthFailure(error?.error, state);
          });
      } else {
        localStorage.setItem('OAuthCode', code);
        if (state) {
          localStorage.setItem('OAuthState', state);
        } else {
          localStorage.removeItem('OAuthState');
        }
        this.setState({ isLoading: false, authSuccess: true });
      }

      this.timer = setTimeout(() => {
        window.close();
      }, 2000);
    };

    if (typeof navigator !== 'undefined' && navigator.locks?.request) {
      navigator.locks.request(lockKey, processAuth);
    } else {
      processAuth();
    }
  }

  handleAuthFailure(errorMessage, state) {
    if (state) {
      localStorage.removeItem(`oauth_flow_${state}`);
    }

    // Only clear global OAuthCode/OAuthState if it belongs to this state,
    // preserving any concurrent, unrelated provider's pending authorization credentials
    const currentOAuthState = localStorage.getItem('OAuthState');
    if (state && currentOAuthState === state) {
      localStorage.removeItem('OAuthCode');
      localStorage.removeItem('OAuthState');
    }

    localStorage.removeItem('oauth_expected_state');
    localStorage.removeItem('oauth_initiating_provider');

    this.setState({
      isLoading: false,
      authSuccess: false,
      error: errorMessage || 'OAuth authorization failed',
    });

    this.timer = setTimeout(() => {
      window.close();
    }, 3000);
  }

  componentWillUnmount() {
    clearTimeout(this.timer);
  }

  render() {
    const { isLoading, authSuccess, error } = this.state;
    return (
      <div
        style={{
          width: '100%',
          height: '100vh',
          backgroundColor: '#ffffff',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {isLoading ? (
          <TJLoader />
        ) : (
          <div>
            {!authSuccess ? (
              <div
                style={{
                  width: '580px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '24px',
                }}
              >
                <div
                  style={{
                    backgroundColor: '#fff0ee',
                    padding: '12px',
                    borderRadius: '12px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                  }}
                >
                  <WarningOctagon fill="#d72d39" width="32" height="32" />
                </div>
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '4px',
                    textAlign: 'center',
                    width: '100%',
                  }}
                >
                  <h4
                    style={{
                      fontSize: '36px',
                      fontFamily: 'IBM Plex Sans, sans-serif',
                      fontWeight: '500',
                      lineHeight: '44px',
                      margin: '0',
                      color: '#000000',
                    }}
                  >
                    Error
                  </h4>
                  <div
                    style={{
                      fontSize: '20px',
                      fontFamily: 'IBM Plex Sans, sans-serif',
                      fontWeight: '400',
                      lineHeight: '32px',
                      color: '#000000',
                    }}
                  >
                    {error || 'An error occurred during authorization'}
                  </div>
                </div>
              </div>
            ) : (
              <div
                style={{
                  width: '580px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '24px',
                }}
              >
                <div
                  style={{
                    backgroundColor: '#E8F3EB',
                    padding: '12px',
                    borderRadius: '12px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                  }}
                >
                  <VerifiedShield fill="#1E823B" width="32" height="32" />
                </div>
                <div
                  style={{
                    width: '580px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                >
                  <h4
                    style={{
                      fontSize: '36px',
                      fontFamily: 'IBM Plex Sans, sans-serif',
                      fontWeight: '500',
                      lineHeight: '44px',
                      margin: '0',
                      color: '#000000',
                    }}
                  >
                    Authorisation successful!
                  </h4>
                  <div
                    style={{
                      fontSize: '20px',
                      fontFamily: 'IBM Plex Sans, sans-serif',
                      fontWeight: '400',
                      lineHeight: '32px',
                      color: '#000000',
                      textAlign: 'center',
                    }}
                  >
                    <div>
                      Authorization successful! You will be redirected in a few seconds. Don’t want to wait?{' '}
                      <span
                        style={{ textDecoration: 'underline', color: '#000000', cursor: 'pointer' }}
                        onClick={() => window.close()}
                      >
                        Click here
                      </span>{' '}
                      to go now.
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }
}

export const Authorize = withTranslation()(withRouter(AuthorizeComponent));
