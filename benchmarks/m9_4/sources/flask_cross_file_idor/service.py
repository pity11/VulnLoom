def load_invoice(invoice_id):
    return Invoice.query.get(invoice_id)
