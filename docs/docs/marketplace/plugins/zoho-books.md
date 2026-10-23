---
id: marketplace-plugin-zoho-books
title: Zoho Books
---

# Zoho Books

The Zoho Books plugin allows you to connect ToolJet applications directly to your Zoho Books accounting account. With this plugin, you can manage organizations, contacts, customer invoices, vendor bills, business expenses, items, customer payments, and chart of accounts.

:::info
**Prerequisite:** Ensure you have configured access to ToolJet Marketplace plugins in your workspace before setting up this integration.
:::

## Overview of Supported Operations

The Zoho Books plugin supports 17 key operations spanning core financial and accounting modules:

* **Organizations**:
  - `List Organizations`: Fetch all organizations associated with your Zoho account. Use this to find your `Organization ID`.
* **Contacts**:
  - `List Contacts`: Query customer and vendor contacts with pagination, sorting, and status filters.
  - `Get Contact`: Retrieve details for a specific contact by `contact_id`.
  - `Create Contact`: Create a new customer or vendor with name, company, email, and billing address.
  - `Update Contact`: Modify an existing contact's attributes.
* **Invoices**:
  - `List Invoices`: List invoices with customer and status filtering (e.g. paid, unpaid, overdue).
  - `Get Invoice`: Retrieve comprehensive invoice details including line items and payment status.
  - `Create Invoice`: Draft or create an invoice with line items, rates, taxes, and customer ID.
  - `Update Invoice`: Update line items or details for an invoice.
  - `Email Invoice`: Send an invoice copy directly to customer email addresses with custom subject and body.
* **Bills**:
  - `List Bills`: Query accounts payable vendor bills with pagination.
  - `Create Bill`: Record vendor bills against accounts and line items.
* **Expenses**:
  - `List Expenses`: Retrieve recorded business expenditures.
  - `Create Expense`: Record an out-of-pocket or direct expense against an expense account and paid-through account.
* **Items**:
  - `List Items`: Fetch the goods and services catalog.
* **Customer Payments**:
  - `Record Customer Payment`: Apply customer payments against outstanding invoices with payment mode, amount, and date.
* **Chart of Accounts**:
  - `List Chart of Accounts`: List general ledger accounts (Assets, Liabilities, Income, Expenses, Equity).

---

## Connection Configuration

### 1. Creating a Zoho Self-Client or Server-based App
1. Navigate to the [Zoho API Console](https://api-console.zoho.com/).
2. Click **Add Client** and select **Server-based Applications** (or Self-Client for internal testing).
3. Set your **Client Name** (e.g., `ToolJet Zoho Books`).
4. In **Authorized Redirect URIs**, provide your ToolJet callback URL:
   ```text
   <TOOLJET_HOST>/oauth2/authorize
   ```
5. Click **Create** to obtain your **Client ID** and **Client Secret**.

### 2. Supported Regional Data Centers
Zoho accounts are bound to regional data centers. Select the region matching your Zoho Books account:
* **United States (.com)**: Auth `https://accounts.zoho.com`, API `https://www.zohoapis.com/books/v3`
* **Europe (.eu)**: Auth `https://accounts.zoho.eu`, API `https://www.zohoapis.eu/books/v3`
* **India (.in)**: Auth `https://accounts.zoho.in`, API `https://www.zohoapis.in/books/v3`
* **Australia (.com.au)**: Auth `https://accounts.zoho.com.au`, API `https://www.zohoapis.com.au/books/v3`
* **Japan (.jp)**: Auth `https://accounts.zoho.jp`, API `https://www.zohoapis.jp/books/v3`
* **Canada (.ca)**: Auth `https://accounts.zoho.ca`, API `https://www.zohoapis.ca/books/v3`
* **Saudi Arabia (.sa)**: Auth `https://accounts.zoho.sa`, API `https://www.zohoapis.sa/books/v3`

### 3. Required OAuth Scopes
By default, the plugin requests:
```text
ZohoBooks.fullaccess.all
```
This enables seamless access to all operations listed above. Alternatively, you can configure granular scopes such as `ZohoBooks.contacts.ALL,ZohoBooks.invoices.ALL,ZohoBooks.settings.READ`.

### 4. Setting Up in ToolJet
1. Open ToolJet and navigate to **Data Sources** &gt; **+ Add new Data source**.
2. Select **Zoho Books** from Marketplace / APIs.
3. Select your **Data Center (Region)**.
4. Enter your **Client ID** and **Client Secret**.
5. Click **Connect to Zoho Books** to initiate OAuth 2.0 consent. ToolJet securely stores the acquired refresh token in an encrypted format.
6. Optional: Enter your **Organization ID** directly, or save and run the `List Organizations` query first to retrieve your organization ID.
7. Click **Test connection** and **Save data source**.

---

## Operations Reference

### Organizations
#### List Organizations
* **Operation**: `list_organizations`
* **Required Parameters**: None.
* **Returns**: Array of Zoho Books organizations available to the user.

### Contacts
#### List Contacts
* **Operation**: `list_contacts`
* **Parameters**:
  - `page` *(optional)*: Page number (default: 1).
  - `per_page` *(optional)*: Results per page (default: 200).
  - `sort_column` *(optional)*: Column to sort by (e.g. `contact_name`).
  - `filter_by` *(optional)*: Filter condition (e.g. `Status.Active`, `Status.All`).

#### Get Contact
* **Operation**: `get_contact`
* **Parameters**:
  - `contact_id` *(required)*: Unique ID of the contact.

#### Create Contact
* **Operation**: `create_contact`
* **Parameters**:
  - `contact_data` *(required)*: JSON object defining contact attributes.
  ```json
  {
    "contact_name": "Acme Global",
    "company_name": "Acme Inc",
    "contact_type": "customer",
    "billing_address": {
      "address": "123 Market St",
      "city": "San Francisco",
      "country": "U.S.A"
    }
  }
  ```

#### Update Contact
* **Operation**: `update_contact`
* **Parameters**:
  - `contact_id` *(required)*: Unique ID of the contact.
  - `contact_data` *(required)*: JSON object with fields to update.

### Invoices
#### List Invoices
* **Operation**: `list_invoices`
* **Parameters**:
  - `customer_id` *(optional)*: Filter invoices by customer.
  - `status` *(optional)*: Filter by invoice status (e.g., `paid`, `unpaid`, `overdue`, `draft`).
  - `page` / `per_page` *(optional)*: Pagination controls.

#### Create Invoice
* **Operation**: `create_invoice`
* **Parameters**:
  - `invoice_data` *(required)*: JSON payload for invoice creation.
  ```json
  {
    "customer_id": "70000000001",
    "line_items": [
      {
        "item_id": "70000000005",
        "rate": 150.0,
        "quantity": 2
      }
    ]
  }
  ```

#### Email Invoice
* **Operation**: `email_invoice`
* **Parameters**:
  - `invoice_id` *(required)*: Invoice ID to be sent.
  - `email_data` *(required)*: JSON containing recipients and body.
  ```json
  {
    "to_mail_ids": ["accounting@client.com"],
    "subject": "Invoice for services rendered",
    "body": "Dear Customer, please find your invoice attached."
  }
  ```

### Bills & Expenses
* **List Bills** / **Create Bill**: Manage accounts payable with vendor allocations.
* **List Expenses** / **Create Expense**: Record out-of-pocket expenses against chart-of-accounts categories.

### Customer Payments
#### Record Customer Payment
* **Operation**: `record_customer_payment`
* **Parameters**:
  - `payment_data` *(required)*:
  ```json
  {
    "customer_id": "70000000001",
    "payment_mode": "cash",
    "amount": 300.0,
    "date": "2026-10-14",
    "invoices": [
      {
        "invoice_id": "70000000002",
        "amount_applied": 300.0
      }
    ]
  }
  ```

### Chart of Accounts
#### List Chart of Accounts
* **Operation**: `list_chart_of_accounts`
* **Parameters**:
  - `filter_by` *(optional)*: Account filters (e.g. `AccountType.Active`, `AccountType.All`).
  - `sort_column` *(optional)*: Column to sort accounts by.

---

## Error Handling and Troubleshooting

| Symptom / Error | Cause | Resolution |
| :--- | :--- | :--- |
| `MISSING_ACCESS_TOKEN` | OAuth handshake not completed | Click **Connect to Zoho Books** in Data Source settings to complete authorization. |
| `MISSING_ORGANIZATION_ID` | Organization ID not configured | Run `List Organizations` to find your organization ID, then add it to the connection settings. |
| `Invalid data center / 401 Unauthorized` | Data Center region mismatch | Verify that the selected region (.com, .eu, .in, etc.) matches the account hosting your Zoho Books organization. |
| `OAuth token expired or invalid (code 57/14)` | Access token expired | ToolJet automatically triggers token refresh using the stored refresh token. Re-authenticate if refresh token was revoked in Zoho API console. |
