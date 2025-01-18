import html as htmllib


def get_scan_info(attack_mode: str) -> tuple:
    """
    return the scan mode and details
    """

    if attack_mode:
        return "full scan mode", "the scanner enumerates services on the target and search for vulnerabilities by simulating attacks"
    else:
        return "enumeration only", "the scanner only enumerates services on the target then exit"


def get_scope_info(scope: str) -> tuple:
    """
    return the scope and details on the scope
    """

    if scope == "full":
        return "Full", "scan for subdomains and try to find services on all port"
    elif scope == "medium":
        return "Medium", "scan target for differents services on most used ports"
    elif scope == "strict":
        return "Strict", "scan for subdomains and others services on found subdomains"


def html_report(self) -> str:
    """
    initialize a HTML report with the target address
    """

    # region header section
    html = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Lincox report on """ + self.address + """</title>
    <link
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
      rel="stylesheet"
    />
    <style>
      body {
        background-color: #f8f9fa;
      }
      .report-header {
        text-align: center;
        margin: 20px 0;
      }
      .table-container {
        margin-top: 20px;
      }

      .accordion-body table {
        width: 100%;
        word-wrap: break-word;  /* Ensures long text breaks within cells */
        table-layout: fixed;    /* Makes the table take up all available width */
      }

      .accordion-item {
        border: 1px solid #ced4da;
      }
      .accordion-header button {
        background-color: #f8f9fa;
        color: #343a40;
      }

    </style>
  </head>
  <body>
    <div class="container">
      <header class="report-header">
        <h1 class="display-4">Lincox Security Scan Report</h1>
        <p class="text-muted">
          Comprehensive results of your scan on <b>""" + self.address + """</b>
        </p>
      </header>
      <!-- Scan Settings Section -->
      <section>
        <h2 class="h4">Scan settings</h2>
        <ul class="list-group">"""

    # endregion

    # region scan settings (mode,scope,ports)
    scan_mode, scan_details = get_scan_info(self.attack_mode)
    scope, scope_details = get_scope_info(self.scope)
    ports = self.ports_args if self.ports_args not in [
        '-', 'all'] else 'all ports from 1 to 65535'
    html += f"""
          <li class="list-group-item">
            <strong>Start Time :</strong> Launched at {self.start.split(' ')[1]} on {self.start.split(' ')[0]}
          </li>
          <li class="list-group-item">
            <strong>End Time :</strong> Finished at {self.end.split(' ')[1]} on {self.end.split(' ')[0]}
          </li>
          <li class="list-group-item">
            <strong>Scan mode :</strong> {scan_mode}, {scan_details}
          </li>
          <li class="list-group-item">
            <strong>Scope :</strong> {scope}, {scope_details}
          </li>
          <li class="list-group-item">
            <strong>Ports scanned :</strong> {ports}
          </li>"""

    html += """
        </ul>
      </section>"""

    # endregion

    # region services detected
    if len(self.services) > 0:
        html += """
        <br>
        <!-- Detected Services Section -->
        <section>
            <h2 class="h4">Detected Services</h2>
            <table class="table table-bordered table-striped">
                    <thead class="table-dark">
                    <tr>
                        <th>Port</th>
                        <th>Name</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>CPE</th>
                        <th>Address</th>
                    </tr>
                    </thead>
                    <tbody>"""

        for service in self.services:
            data = self.services[service]
            service_info = f"{data["name"]}/{data["product"]}"

            if data["product"] == '':
                service_info = data["name"]

            if data["name"] == '':
                service_info = data["product"]

            if data["product"] == '' and data["name"] == '':
                service_info = "unknown"

            html += f"""
            <tr>
                <td>{service}</td>
                <td>{data["name"] if data["name"] != '' else "unknown"}</td>
                <td>{data["product"] if data["product"] != '' else ""}</td>
                <td>{data["version"] if data["version"] != '' else ""}</td>
                <td>{data["cpe"] if data["cpe"] != '' else ""}</td>
                <td>{self.address}</td>
            </tr>
            """

        html += """
                </tbody>
            </table>
        </section>"""

    # endregion

    # region domains

    if hasattr(self, "domains"):
        html += f"""
        <!-- Detected Domains Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Detected Domains</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#collapseDomains" aria-expanded="false" aria-controls="collapseDomains">
                            View Detected Domains ({len(self.domains)})
                        </button>
                    </h2>
                    <div id="collapseDomains" class="accordion-collapse collapse" aria-labelledby="headingDomains"
                        data-bs-parent="#domainsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Domains</th>
                                        <!-- <th>IP Address</th> -->
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for finding, status in self.domains:
            html += f"""
                                    <tr>
                                        <td><a href="http://{finding}">{finding}</a></td>
                                        <td>{status}</td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
    # endregion

    # region Crawled URLs
    if len(self.crawled_urls) > 0:
        html += f"""
        <!-- Detected URLs Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found URLs (Crawler)</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#collapseCrawledURLs" aria-expanded="false" aria-controls="collapseCrawledURLs">
                            View Detected URLs ({len(self.crawled_urls)})
                        </button>
                    </h2>
                    <div id="collapseCrawledURLs" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                        data-bs-parent="#urlsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>URL</th>
                                        <th>Response</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for url, code in self.crawled_urls:
            html += f"""
                                    <tr>
                                        <td><a href="{url}">{url}</a></td>
                                        <td>{code}</td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
    # endregion

    # region Fuzzed URLs
    if len(self.fuzzed_urls) > 0:
        html += f"""
        <!-- Detected URLs Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found URLs (Fuzzer)</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#collapseFuzzedURLs" aria-expanded="false" aria-controls="collapseFuzzedURLs">
                            View Detected URLs ({len(self.fuzzed_urls)})
                        </button>
                    </h2>
                    <div id="collapseFuzzedURLs" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                        data-bs-parent="#urlsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>URL</th>
                                        <th>Response</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for url, code in self.fuzzed_urls:
            html += f"""
                                    <tr>
                                        <td><a href="{url}">{url}</a></td>
                                        <td>{code}</td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
    # endregion

    # region Found Headers
    if len(self.found_headers) > 0:
        section = "collapseHeaders"
        html += f"""
        <!-- Detected Headers Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found Headers</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                            View Detected headers ({len(self.found_headers)})
                        </button>
                    </h2>
                    <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                        data-bs-parent="#urlsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Header</th>
                                        <th>Value</th>
                                        <th>URL</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for header, value, url in self.found_headers:
            html += f"""
                                    <tr>
                                        <td>{header}</td>
                                        <td>{value}</td>
                                        <td><a href="{url}">{url}</a></td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
    # endregion

    # region Found Data
    if len(self.found_data) > 0:
        html += """
        <!-- Detected Data Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Interesting Data on Technologies used and/or credentials</h2>"""

        # region CMS
        if len([x for x in self.found_data if x['type'] == 'CMS']) > 0:
            section = "collapseCMSFoundData"
            html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected CMS ({len([x for x in self.found_data if x['type'] == 'CMS'])})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>Type</th>
                                            <th>HTML line</th>
                                            <th>URL</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            for data in self.found_data:
                if data['type'] != "CMS":
                    continue
                html += f"""
                                        <tr>
                                            <td>{data['name']}</td>
                                            <td>{data['line']}</td>
                                            <td><a href="{data['url']}">{data['url']}</a></td>
                                        </tr>
                """

            html += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            """
        # endregion

        # region Credentials
        if len([x for x in self.found_data if x['type'] == 'credential']) > 0:
            section = "collapseCredentialsFoundData"
            html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected Credentials ({len([x for x in self.found_data if x['type'] == 'credential'])})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>Type</th>
                                            <th>HTML line</th>
                                            <th>URL</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            for data in self.found_data:
                if data['type'] != "credential":
                    continue
                html += f"""
                                        <tr>
                                            <td>{data['name']}</td>
                                            <td>{data['line']}</td>
                                            <td><a href="{data['url']}">{data['url']}</a></td>
                                        </tr>
                """

            html += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            """
        # endregion

        # region Comments
        if len([x for x in self.found_data if x['type'] == 'other']) > 0:
            section = "collapseCommentsFoundData"
            html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected Comments ({len([x for x in self.found_data if x['type'] == 'other'])})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>Type</th>
                                            <th>HTML line</th>
                                            <th>URL</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            for data in self.found_data:
                if data['type'] != "other":
                    continue
                html += f"""
                                        <tr>
                                            <td>{data['name']}</td>
                                            <td>{data['line']}</td>
                                            <td><a href="{data['url']}">{data['url']}</a></td>
                                        </tr>
                """

            html += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            """
        # endregion

        html += "</section>"
    # endregion

    # region Found parameter
    if len(self.url_parameters) > 0:
        section = "collapseParameters"
        html += f"""
        <!-- Detected URLs Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found Parameters</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                            View Detected parameters ({len(self.url_parameters)})
                        </button>
                    </h2>
                    <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                        data-bs-parent="#urlsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Name</th>
                                        <th>Method</th>
                                        <th>Response</th>
                                        <th>Size</th>
                                        <th>URL</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for url, name, response, size, method, type, origin in self.url_parameters:
            html += f"""
                                    <tr>
                                        <td>{name}</td>
                                        <td>{method}</td>
                                        <td>{response}</td>
                                        <td>{size}</td>
                                        <td><a href="{url}">{url}</a></td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
        # endregion

    # region Found XSS
    if len(self.found_xss) > 0:
        section = "collapseXSS"
        html += f"""
        <!-- Detected URLs Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found XSS</h2>

            <div class="accordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                            data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                            View Detected parameters ({len(self.found_xss)})
                        </button>
                    </h2>
                    <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                        data-bs-parent="#urlsAccordion">
                        <div class="accordion-body">
                            <table class="table table-bordered table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Type</th>
                                        <th>URL</th>
                                        <th>Method</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for url, parameter, method, type, confidence in self.found_xss:
            html += f"""
                                    <tr>
                                        <td>{type}</td>
                                        <td><a href="{url}/?{parameter}=here">{url}/?{parameter}=here</a></td>
                                        <td>{method}</td>
                                    </tr>
            """

        html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        """
        # endregion

    html += """
    <section class="accordion mt-4" id="additional-findings">
        <h2 class="h4">Additional Findings</h2>

        <div class="accordion-item">
        <h2 class="accordion-header" id="headingOne">
            <button
            class="accordion-button"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#collapseOne"
            aria-expanded="true"
            aria-controls="collapseOne"
            >
            Vulnerabilities
            </button>
        </h2>
        <div
            id="collapseOne"
            class="accordion-collapse collapse show"
            aria-labelledby="headingOne"
            data-bs-parent="#additional-findings"
        >
            <div class="accordion-body">
            <ul>
                <li>
                SQL Injection vulnerability detected on `/login` endpoint
                </li>
                <li>
                Cross-Site Scripting (XSS) detected on `/search` endpoint
                </li>
                <li>Insecure Cookies found in HTTP responses</li>
            </ul>
            </div>
        </div>
        </div>

        <div class="accordion-item">
        <h2 class="accordion-header" id="headingTwo">
            <button
            class="accordion-button collapsed"
            type="button"
            data-bs-toggle="collapse"
            data-bs-target="#collapseTwo"
            aria-expanded="false"
            aria-controls="collapseTwo"
            >
            Recommendations
            </button>
        </h2>
        <div
            id="collapseTwo"
            class="accordion-collapse collapse"
            aria-labelledby="headingTwo"
            data-bs-parent="#additional-findings"
        >
            <div class="accordion-body">
            <ol>
                <li>
                Implement parameterized queries to prevent SQL Injection
                </li>
                <li>
                Use Content Security Policy (CSP) to mitigate XSS attacks
                </li>
                <li>Set `HttpOnly` and `Secure` flags on cookies</li>
            </ol>
            </div>
        </div>
        </div>
    </section>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    return html
