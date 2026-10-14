export type SourceOptions = {
  client_id?: { value: string };
  client_secret?: { value: string };
  region?: { value: string };
  organization_id?: { value: string };
  access_token?: string;
  refresh_token?: string;
  scopes?: { value: string };
  tj_redirect_host?: { value: string };
  multiple_auth_enabled?: boolean;
  tokenData?: Record<string, unknown>;
  [key: string]: unknown;
};

export type QueryOptions = {
  operation: string;
  // Common pagination/filtering
  page?: string;
  per_page?: string;
  sort_column?: string;
  sort_order?: string;
  filter_by?: string;
  status?: string;
  organization_id?: string;

  // Contact operations
  contact_id?: string;
  contact_data?: string;

  // Invoice operations
  invoice_id?: string;
  invoice_data?: string;
  customer_id?: string;
  invoice_number?: string;
  email_data?: string;

  // Bill operations
  bill_id?: string;
  bill_data?: string;
  vendor_id?: string;

  // Expense operations
  expense_id?: string;
  expense_data?: string;

  // Customer Payment operations
  payment_data?: string;

  [key: string]: unknown;
};
