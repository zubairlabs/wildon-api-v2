/// HTML invoice template for Wildon.
///
/// Placeholders use `{{variable}}` syntax for server-side rendering.
/// Design: clean black text on white background, Wildon branding.
pub fn render_invoice_html(
    invoice_ref: &str,
    invoice_date: &str,
    due_date: &str,
    customer_name: &str,
    account_number: &str,
    customer_email: &str,
    items: &[(String, u32, String, String)], // (description, qty, unit_price, total)
    subtotal: &str,
    tax_label: &str,
    tax_amount: &str,
    total: &str,
    payment_method: &str,
    status: &str,
) -> String {
    let mut rows = String::new();
    for (desc, qty, unit, item_total) in items {
        rows.push_str(&format!(
            r#"<tr>
                <td style="padding:12px 16px;border-bottom:1px solid #E5E7EB;">{desc}</td>
                <td style="padding:12px 16px;border-bottom:1px solid #E5E7EB;text-align:center;">{qty}</td>
                <td style="padding:12px 16px;border-bottom:1px solid #E5E7EB;text-align:right;">{unit}</td>
                <td style="padding:12px 16px;border-bottom:1px solid #E5E7EB;text-align:right;">{item_total}</td>
            </tr>"#
        ));
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Invoice {invoice_ref}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #111827;
    background: #FFFFFF;
    margin: 0;
    padding: 40px;
    line-height: 1.6;
  }}
  .invoice-container {{
    max-width: 800px;
    margin: 0 auto;
    background: #FFFFFF;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 48px;
  }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .logo-icon {{
    width: 40px;
    height: 40px;
    background: #111827;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .logo-icon svg {{
    width: 24px;
    height: 24px;
  }}
  .logo-text {{
    font-size: 20px;
    font-weight: 700;
    color: #111827;
  }}
  .invoice-title {{
    font-size: 32px;
    font-weight: 700;
    color: #111827;
    text-transform: uppercase;
    letter-spacing: 2px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 32px;
    margin-bottom: 40px;
  }}
  .meta-section h3 {{
    font-size: 12px;
    font-weight: 600;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0 0 8px 0;
  }}
  .meta-section p {{
    margin: 4px 0;
    font-size: 14px;
    color: #374151;
  }}
  .meta-section .value {{
    font-weight: 600;
    color: #111827;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
  }}
  thead th {{
    padding: 12px 16px;
    font-size: 12px;
    font-weight: 600;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #111827;
    text-align: left;
  }}
  thead th:nth-child(2) {{ text-align: center; }}
  thead th:nth-child(3),
  thead th:nth-child(4) {{ text-align: right; }}
  .totals {{
    display: flex;
    justify-content: flex-end;
    margin-bottom: 40px;
  }}
  .totals-table {{
    width: 280px;
  }}
  .totals-table .row {{
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    font-size: 14px;
    color: #374151;
  }}
  .totals-table .row.total {{
    border-top: 2px solid #111827;
    padding-top: 12px;
    margin-top: 4px;
    font-size: 18px;
    font-weight: 700;
    color: #111827;
  }}
  .payment-info {{
    display: flex;
    justify-content: space-between;
    padding: 20px 24px;
    background: #F9FAFB;
    border-radius: 8px;
    margin-bottom: 40px;
    font-size: 14px;
  }}
  .payment-info .label {{
    color: #6B7280;
  }}
  .payment-info .value {{
    font-weight: 600;
    color: #111827;
  }}
  .status-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .status-paid {{
    background: #D1FAE5;
    color: #065F46;
  }}
  .status-pending {{
    background: #FEF3C7;
    color: #92400E;
  }}
  .status-overdue {{
    background: #FEE2E2;
    color: #991B1B;
  }}
  .footer {{
    text-align: center;
    padding-top: 32px;
    border-top: 1px solid #E5E7EB;
    font-size: 13px;
    color: #9CA3AF;
  }}
  .footer a {{
    color: #6B7280;
    text-decoration: none;
  }}
</style>
</head>
<body>
<div class="invoice-container">
  <!-- Header -->
  <div class="header">
    <div class="logo">
      <div class="logo-icon">
        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 2L2 7L12 12L22 7L12 2Z" fill="white"/>
          <path d="M2 17L12 22L22 17" stroke="white" stroke-width="2" stroke-linecap="round"/>
          <path d="M2 12L12 17L22 12" stroke="white" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <span class="logo-text">Wildon</span>
    </div>
    <div class="invoice-title">Invoice</div>
  </div>

  <!-- Meta -->
  <div class="meta-grid">
    <div class="meta-section">
      <h3>Invoice Details</h3>
      <p>Invoice: <span class="value">{invoice_ref}</span></p>
      <p>Date: <span class="value">{invoice_date}</span></p>
      <p>Due Date: <span class="value">{due_date}</span></p>
    </div>
    <div class="meta-section">
      <h3>Bill To</h3>
      <p class="value">{customer_name}</p>
      <p>Account: <span class="value">{account_number}</span></p>
      <p>{customer_email}</p>
    </div>
  </div>

  <!-- Line Items -->
  <table>
    <thead>
      <tr>
        <th>Description</th>
        <th>Qty</th>
        <th>Unit Price</th>
        <th>Total</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <!-- Totals -->
  <div class="totals">
    <div class="totals-table">
      <div class="row">
        <span>Subtotal</span>
        <span>{subtotal}</span>
      </div>
      <div class="row">
        <span>{tax_label}</span>
        <span>{tax_amount}</span>
      </div>
      <div class="row total">
        <span>Total</span>
        <span>{total}</span>
      </div>
    </div>
  </div>

  <!-- Payment Info -->
  <div class="payment-info">
    <div>
      <span class="label">Payment Method: </span>
      <span class="value">{payment_method}</span>
    </div>
    <div>
      <span class="label">Status: </span>
      <span class="status-badge status-{status_class}">{status}</span>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <p>Wildon &middot; <a href="https://wildon.com.au">wildon.com.au</a></p>
    <p>support@wildon.com.au</p>
  </div>
</div>
</body>
</html>"##,
        invoice_ref = invoice_ref,
        invoice_date = invoice_date,
        due_date = due_date,
        customer_name = customer_name,
        account_number = account_number,
        customer_email = customer_email,
        rows = rows,
        subtotal = subtotal,
        tax_label = tax_label,
        tax_amount = tax_amount,
        total = total,
        payment_method = payment_method,
        status = status,
        status_class = status.to_lowercase().replace(' ', "-"),
    )
}
