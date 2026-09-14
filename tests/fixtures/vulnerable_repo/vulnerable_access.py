# Vulnerable Path Traversal
def read_invoice_document(request):
    filename = request.args.get("doc")
    # Flaw: RULE_A01_PATH_TRAVERSAL
    with open("/var/invoices/" + filename, "r") as f:
        return f.read()
