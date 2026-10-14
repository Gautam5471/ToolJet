import {
  QueryError,
  QueryService,
  QueryResult,
  ConnectionTestResult,
  OAuthUnauthorizedClientError,
  getCurrentToken,
  User,
  App,
} from '@tooljet-marketplace/common';
import { SourceOptions, QueryOptions } from './types';
import got, { OptionsOfJSONResponseBody, Response } from 'got';
import * as crypto from 'crypto';

interface RegionConfig {
  authUrl: string;
  tokenUrl: string;
  apiUrl: string;
}

const REGION_CONFIGS: Record<string, RegionConfig> = {
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

function getOption(options: unknown, key: string): string | undefined {
  if (Array.isArray(options)) {
    const item = options.find((i: { key?: string; value?: unknown }) => i?.key === key);
    if (item && item.value !== undefined && item.value !== null) {
      return String(item.value);
    }
  } else if (typeof options === 'object' && options !== null) {
    const val = (options as Record<string, unknown>)[key];
    if (typeof val === 'object' && val !== null && 'value' in val) {
      const inner = (val as { value?: unknown }).value;
      return inner !== undefined && inner !== null ? String(inner) : undefined;
    }
    if (val !== undefined && val !== null) {
      return String(val);
    }
  }
  return undefined;
}

function parseJsonBody(content: unknown, fieldName: string): Record<string, unknown> {
  if (!content) return {};
  if (typeof content === 'object') return content as Record<string, unknown>;
  if (typeof content === 'string') {
    const trimmed = content.trim();
    if (!trimmed) return {};
    try {
      return JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      throw new QueryError(
        'Invalid JSON',
        `Field "${fieldName}" contains invalid JSON: ${trimmed.substring(0, 100)}`,
        {}
      );
    }
  }
  return {};
}

export default class ZohoBooks implements QueryService {
  private getRegionConfig(sourceOptions: unknown): RegionConfig {
    const region = (getOption(sourceOptions, 'region') || 'com').toLowerCase();
    return REGION_CONFIGS[region] || REGION_CONFIGS.com;
  }

  authUrl(sourceOptions: SourceOptions): string {
    const host = getOption(sourceOptions, 'tj_redirect_host') || process.env.TOOLJET_HOST || '';
    const subpath = process.env.SUB_PATH || '/';
    const redirectUri = `${host}${subpath.endsWith('/') ? subpath : subpath + '/'}oauth2/authorize`;

    const clientId = getOption(sourceOptions, 'client_id');
    if (!clientId) {
      throw new QueryError('Invalid configuration', 'Missing OAuth credentials: "client_id" not provided.', {
        code: 'MISSING_CLIENT_ID',
      });
    }

    const scopes = getOption(sourceOptions, 'scopes') || 'ZohoBooks.fullaccess.all';
    const regionConfig = this.getRegionConfig(sourceOptions);

    const clientSecret = getOption(sourceOptions, 'client_secret') || '';
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now().toString();
    const hmacSecret = clientSecret || clientId;
    const sig = crypto.createHmac('sha256', hmacSecret).update(`${nonce}:${timestamp}`).digest('hex');
    const state = `${nonce}:${timestamp}:${sig}`;

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      scope: scopes,
      redirect_uri: redirectUri,
      access_type: 'offline',
      prompt: 'consent',
      state,
    });

    return `${regionConfig.authUrl}?${params.toString()}`;
  }

  public validateState(state: string | undefined, clientId: string, clientSecret: string): boolean {
    if (!state || typeof state !== 'string') {
      return false;
    }
    const parts = state.split(':');
    if (parts.length !== 3) {
      return false;
    }
    const [nonce, timestampStr, sig] = parts;
    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return false;
    }
    // Allow up to 1 hour (3600 seconds) for OAuth flow completion
    const now = Date.now();
    if (now - timestamp > 60 * 60 * 1000 || timestamp > now + 5 * 60 * 1000) {
      return false;
    }
    const hmacSecret = clientSecret || clientId;
    const expectedSig = crypto.createHmac('sha256', hmacSecret).update(`${nonce}:${timestampStr}`).digest('hex');
    if (sig.length !== expectedSig.length) {
      return false;
    }
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expectedSig, 'hex'));
  }

  async accessDetailsFrom(
    authCode: string,
    sourceOptions: unknown,
    resetSecureData = false
  ): Promise<[string, string][]> {
    if (resetSecureData) {
      return [
        ['access_token', ''],
        ['refresh_token', ''],
      ];
    }

    const clientId = getOption(sourceOptions, 'client_id');
    const clientSecret = getOption(sourceOptions, 'client_secret');
    if (!clientId || !clientSecret) {
      throw new QueryError('Invalid configuration', 'Missing client_id or client_secret for OAuth token exchange.', {});
    }

    // Validate OAuth state to prevent CSRF / mismatched callbacks
    const skipStateValidation = getOption(sourceOptions, 'skip_state_validation') === 'true';
    if (!skipStateValidation) {
      const state = getOption(sourceOptions, 'state');
      if (!state) {
        throw new QueryError('Invalid OAuth state', 'Missing OAuth state parameter.', {
          code: 'MISSING_OAUTH_STATE',
        });
      }
      if (!this.validateState(state, clientId, clientSecret)) {
        throw new QueryError('Invalid OAuth state', 'Mismatched or expired OAuth state parameter.', {
          code: 'INVALID_OAUTH_STATE',
        });
      }
    }

    const host = getOption(sourceOptions, 'tj_redirect_host') || process.env.TOOLJET_HOST || '';
    const subpath = process.env.SUB_PATH || '/';
    const redirectUri = `${host}${subpath.endsWith('/') ? subpath : subpath + '/'}oauth2/authorize`;

    const regionConfig = this.getRegionConfig(sourceOptions);

    const bodyParams = new URLSearchParams({
      code: authCode,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });

    try {
      const response = await got.post(regionConfig.tokenUrl, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: bodyParams.toString(),
        responseType: 'json',
      });

      const body = response.body as {
        access_token?: string;
        refresh_token?: string;
        error?: string;
        error_description?: string;
      };

      if (body.error) {
        throw new QueryError('Token exchange failed', body.error_description || body.error, {
          error: body.error,
        });
      }

      if (!body.access_token) {
        throw new QueryError('Token exchange failed', 'No access_token returned by Zoho', {});
      }

      return [
        ['access_token', body.access_token],
        ['refresh_token', body.refresh_token || ''],
      ];
    } catch (error: unknown) {
      if (error instanceof QueryError) throw error;
      const gotErr = error as { response?: { statusCode?: number; body?: unknown }; message?: string };
      const resBody = gotErr.response?.body;
      const errMsg =
        typeof resBody === 'object' && resBody !== null && 'error' in resBody
          ? String((resBody as { error: unknown }).error)
          : gotErr.message || 'Token exchange failed';
      throw new QueryError('Failed to retrieve access tokens', errMsg, {
        statusCode: gotErr.response?.statusCode,
      });
    }
  }

  async refreshToken(
    sourceOptions: Record<string, unknown>,
    _dataSourceId?: string,
    userId?: string,
    isAppPublic?: boolean
  ): Promise<{ access_token: string; refresh_token: string }> {
    const isMultiAuthEnabled = Boolean(sourceOptions['multiple_auth_enabled']);
    const currentToken = isMultiAuthEnabled
      ? getCurrentToken(true, sourceOptions['tokenData'] as Record<string, unknown>, userId || '', Boolean(isAppPublic))
      : null;

    const refreshTokenValue = isMultiAuthEnabled
      ? (currentToken?.['refresh_token'] as string | undefined)
      : (sourceOptions['refresh_token'] as string | undefined);

    if (!refreshTokenValue) {
      throw new QueryError('Token refresh failed', 'Missing refresh_token for Zoho Books', {
        code: 'MISSING_REFRESH_TOKEN',
      });
    }

    const clientId = getOption(sourceOptions, 'client_id');
    const clientSecret = getOption(sourceOptions, 'client_secret');
    if (!clientId || !clientSecret) {
      throw new QueryError('Token refresh failed', 'Missing client_id or client_secret', {});
    }

    const regionConfig = this.getRegionConfig(sourceOptions);

    const bodyParams = new URLSearchParams({
      refresh_token: refreshTokenValue,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: 'refresh_token',
    });

    try {
      const response = await got.post(regionConfig.tokenUrl, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: bodyParams.toString(),
        responseType: 'json',
      });

      const body = response.body as {
        access_token?: string;
        refresh_token?: string;
        error?: string;
        error_description?: string;
      };

      if (body.error) {
        throw new QueryError('Token refresh failed', body.error_description || body.error, {
          error: body.error,
        });
      }

      if (!body.access_token) {
        throw new QueryError('Token refresh failed', 'No access_token returned by Zoho Books', {});
      }

      return {
        access_token: body.access_token,
        refresh_token: body.refresh_token || refreshTokenValue,
      };
    } catch (error: unknown) {
      if (error instanceof QueryError) throw error;
      const gotErr = error as { response?: { statusCode?: number; body?: unknown }; message?: string };
      const resBody = gotErr.response?.body;
      const errMsg =
        typeof resBody === 'object' && resBody !== null && 'error' in resBody
          ? String((resBody as { error: unknown }).error)
          : gotErr.message || 'Token refresh failed';
      throw new QueryError('Zoho Books token refresh error', errMsg, {
        statusCode: gotErr.response?.statusCode,
      });
    }
  }

  async testConnection(sourceOptions: SourceOptions): Promise<ConnectionTestResult> {
    try {
      const result = await this.executeRequest(
        sourceOptions,
        {
          method: 'GET',
          path: '/organizations',
        },
        false
      );

      if (result && typeof result === 'object') {
        return { status: 'ok', message: 'Successfully connected to Zoho Books' };
      }
      return { status: 'failed', message: 'Could not connect to Zoho Books' };
    } catch (error: unknown) {
      const errMsg = error instanceof Error ? error.message : 'Connection test failed';
      return { status: 'failed', message: errMsg };
    }
  }

  private async executeRequest(
    sourceOptions: SourceOptions,
    options: {
      method: 'GET' | 'POST' | 'PUT' | 'DELETE';
      path: string;
      searchParams?: Record<string, string>;
      body?: Record<string, unknown>;
    },
    requireOrgId = true,
    context?: { user?: User; app?: App }
  ): Promise<object | object[]> {
    const isMultiAuthEnabled = Boolean(sourceOptions['multiple_auth_enabled']);
    const accessToken = isMultiAuthEnabled
      ? (getCurrentToken(
          true,
          sourceOptions['tokenData'] as Record<string, unknown>,
          context?.user?.id || '',
          Boolean(context?.app?.isPublic)
        )?.['access_token'] as string | undefined)
      : (sourceOptions['access_token'] as string | undefined);

    if (!accessToken) {
      throw new QueryError(
        'Authentication required',
        'No access token found. Please authenticate with Zoho Books first.',
        { code: 'MISSING_ACCESS_TOKEN' }
      );
    }

    const orgId = getOption(sourceOptions, 'organization_id');
    if (requireOrgId && !orgId) {
      throw new QueryError(
        'Invalid configuration',
        'Missing Zoho Books Organization ID. Please configure it in the data source settings or fetch it with "List Organizations".',
        { code: 'MISSING_ORGANIZATION_ID' }
      );
    }

    const regionConfig = this.getRegionConfig(sourceOptions);
    const url = `${regionConfig.apiUrl}${options.path}`;

    const searchParams = new URLSearchParams();
    if (requireOrgId && orgId) {
      searchParams.append('organization_id', orgId);
    }
    if (options.searchParams) {
      for (const [key, val] of Object.entries(options.searchParams)) {
        if (val !== undefined && val !== null && String(val).trim() !== '') {
          searchParams.append(key, String(val).trim());
        }
      }
    }

    const requestOptions: OptionsOfJSONResponseBody = {
      method: options.method,
      headers: {
        Authorization: `Zoho-oauthtoken ${accessToken}`,
        Accept: 'application/json',
      },
      searchParams,
      responseType: 'json',
    };

    if (requireOrgId && orgId) {
      (requestOptions.headers as Record<string, string>)['X-com-zoho-invoice-organizationid'] = orgId;
    }

    if (options.body && ['POST', 'PUT'].includes(options.method)) {
      requestOptions.json = options.body;
      (requestOptions.headers as Record<string, string>)['Content-Type'] = 'application/json;charset=UTF-8';
    }

    try {
      const response: Response<unknown> = await got(url, requestOptions);
      const resBody = response.body;

      if (typeof resBody === 'object' && resBody !== null) {
        const bodyObj = resBody as { code?: number; message?: string };
        if (bodyObj.code !== undefined && bodyObj.code !== 0) {
          if (bodyObj.code === 14) {
            throw new OAuthUnauthorizedClientError(
              'OAuth token expired or invalid',
              bodyObj.message || 'Token invalid',
              bodyObj
            );
          }
          throw new QueryError('Zoho Books API error', bodyObj.message || 'API request failed', {
            code: bodyObj.code,
            response: bodyObj,
          });
        }
        return resBody as object;
      }
      return { response: resBody } as object;
    } catch (error: unknown) {
      if (error instanceof QueryError || error instanceof OAuthUnauthorizedClientError) {
        throw error;
      }

      const gotErr = error as {
        response?: { statusCode?: number; body?: unknown };
        message?: string;
        code?: string;
      };
      const statusCode = gotErr.response?.statusCode;

      if (statusCode === 401 || statusCode === 403) {
        throw new OAuthUnauthorizedClientError(
          'OAuth token expired or invalid',
          gotErr.message || 'Unauthorized',
          gotErr
        );
      }

      const body = gotErr.response?.body;
      let errMsg = gotErr.message || 'Query execution failed';
      let errCode: unknown = gotErr.code;

      if (typeof body === 'object' && body !== null) {
        const b = body as { message?: string; code?: number };
        if (b.message) errMsg = b.message;
        if (b.code !== undefined) errCode = b.code;
      }

      throw new QueryError('Query execution failed', errMsg, {
        statusCode,
        code: errCode,
      });
    }
  }

  async run(
    sourceOptions: SourceOptions,
    queryOptions: QueryOptions,
    _dataSourceId: string,
    _dataSourceUpdatedAt?: string,
    context?: { user?: User; app?: App }
  ): Promise<QueryResult> {
    const operation = queryOptions?.operation;
    if (!operation) {
      throw new QueryError('Invalid operation', 'No operation specified.', {});
    }

    let data: object | object[];

    switch (operation) {
      case 'list_organizations': {
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/organizations',
          },
          false,
          context
        );
        break;
      }

      case 'list_contacts': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.page) searchParams.page = queryOptions.page;
        if (queryOptions.per_page) searchParams.per_page = queryOptions.per_page;
        if (queryOptions.sort_column) searchParams.sort_column = queryOptions.sort_column;
        if (queryOptions.filter_by) searchParams.filter_by = queryOptions.filter_by;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/contacts',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      case 'get_contact': {
        const contactId = queryOptions.contact_id;
        if (!contactId) {
          throw new QueryError('Missing parameter', 'Contact ID is required for get_contact.', {});
        }
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: `/contacts/${encodeURIComponent(contactId)}`,
          },
          true,
          context
        );
        break;
      }

      case 'create_contact': {
        const body = parseJsonBody(queryOptions.contact_data, 'contact_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: '/contacts',
            body,
          },
          true,
          context
        );
        break;
      }

      case 'update_contact': {
        const contactId = queryOptions.contact_id;
        if (!contactId) {
          throw new QueryError('Missing parameter', 'Contact ID is required for update_contact.', {});
        }
        const body = parseJsonBody(queryOptions.contact_data, 'contact_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'PUT',
            path: `/contacts/${encodeURIComponent(contactId)}`,
            body,
          },
          true,
          context
        );
        break;
      }

      case 'list_invoices': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.page) searchParams.page = queryOptions.page;
        if (queryOptions.per_page) searchParams.per_page = queryOptions.per_page;
        if (queryOptions.customer_id) searchParams.customer_id = queryOptions.customer_id;
        if (queryOptions.status) searchParams.status = queryOptions.status;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/invoices',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      case 'get_invoice': {
        const invoiceId = queryOptions.invoice_id;
        if (!invoiceId) {
          throw new QueryError('Missing parameter', 'Invoice ID is required for get_invoice.', {});
        }
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: `/invoices/${encodeURIComponent(invoiceId)}`,
          },
          true,
          context
        );
        break;
      }

      case 'create_invoice': {
        const body = parseJsonBody(queryOptions.invoice_data, 'invoice_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: '/invoices',
            body,
          },
          true,
          context
        );
        break;
      }

      case 'update_invoice': {
        const invoiceId = queryOptions.invoice_id;
        if (!invoiceId) {
          throw new QueryError('Missing parameter', 'Invoice ID is required for update_invoice.', {});
        }
        const body = parseJsonBody(queryOptions.invoice_data, 'invoice_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'PUT',
            path: `/invoices/${encodeURIComponent(invoiceId)}`,
            body,
          },
          true,
          context
        );
        break;
      }

      case 'email_invoice': {
        const invoiceId = queryOptions.invoice_id;
        if (!invoiceId) {
          throw new QueryError('Missing parameter', 'Invoice ID is required for email_invoice.', {});
        }
        const body = parseJsonBody(queryOptions.email_data, 'email_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: `/invoices/${encodeURIComponent(invoiceId)}/email`,
            body,
          },
          true,
          context
        );
        break;
      }

      case 'list_bills': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.page) searchParams.page = queryOptions.page;
        if (queryOptions.per_page) searchParams.per_page = queryOptions.per_page;
        if (queryOptions.vendor_id) searchParams.vendor_id = queryOptions.vendor_id;
        if (queryOptions.status) searchParams.status = queryOptions.status;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/bills',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      case 'create_bill': {
        const body = parseJsonBody(queryOptions.bill_data, 'bill_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: '/bills',
            body,
          },
          true,
          context
        );
        break;
      }

      case 'list_expenses': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.page) searchParams.page = queryOptions.page;
        if (queryOptions.per_page) searchParams.per_page = queryOptions.per_page;
        if (queryOptions.sort_column) searchParams.sort_column = queryOptions.sort_column;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/expenses',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      case 'create_expense': {
        const body = parseJsonBody(queryOptions.expense_data, 'expense_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: '/expenses',
            body,
          },
          true,
          context
        );
        break;
      }

      case 'list_items': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.page) searchParams.page = queryOptions.page;
        if (queryOptions.per_page) searchParams.per_page = queryOptions.per_page;
        if (queryOptions.filter_by) searchParams.filter_by = queryOptions.filter_by;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/items',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      case 'record_customer_payment': {
        const body = parseJsonBody(queryOptions.payment_data, 'payment_data');
        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'POST',
            path: '/customerpayments',
            body,
          },
          true,
          context
        );
        break;
      }

      case 'list_chart_of_accounts': {
        const searchParams: Record<string, string> = {};
        if (queryOptions.filter_by) searchParams.filter_by = queryOptions.filter_by;
        if (queryOptions.sort_column) searchParams.sort_column = queryOptions.sort_column;

        data = await this.executeRequest(
          sourceOptions,
          {
            method: 'GET',
            path: '/chartofaccounts',
            searchParams,
          },
          true,
          context
        );
        break;
      }

      default:
        throw new QueryError('Invalid operation', `Unknown operation "${operation}"`, {});
    }

    return { status: 'ok', data };
  }
}
