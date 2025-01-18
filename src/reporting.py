from html import escape
from urllib.parse import quote_plus
import json

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
        return "Strict", "only scan the given target, (no ports and subdomains enumeration)"


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
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
      body {
        background-color: #f8f9fa;
        margin-bottom: 50px;
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
        word-wrap: break-word;
        table-layout: fixed;
      }

      .accordion-item {
        border: 1px solid #ced4da;
      }
      .accordion-header button {
        background-color: #f8f9fa;
        color: #343a40;
      }

      .graph-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
      }
      canvas {
        height: 300px !important;
        width: 100%;
      }
      .card {
        flex: 1;
      }
      .card-body {
        display: flex;
        align-items: center;
        justify-content: center;
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
            <strong>Scan target :</strong> {self.target}
          </li>
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

    if self.attack_mode:
        # simple graph summary of findings
        html += """
        <div class="container mt-5">
            <h2 class="mb-4">Summary of findings :</h2>
            <div class="graph-container">
                <!-- Pie Graph -->
                <div class="card">
                    <div class="card-body">
                    <canvas id="pieChart"></canvas>
                    </div>
                </div>
                <!-- Column Graph -->
                <div class="card">
                    <div class="card-body">
                    <canvas id="columnChart"></canvas>
                    </div>
                </div>
            </div>
            <center><h3><a href="#findings-reporting">Go to findings reporting</a></h3></center>
        </div>
        <h2 style="margin-top: 50px;" class="mb-4">Enumeration reporting :</h2>
        """        

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

    if len(self.url_parameters) > 0 or len(self.forms_list):
        html += """
        <!-- Detected parameters Section -->
        <section class="table-container">
            <h2 class="h4 mt-4">Found Parameters</h2>"""

        # region url parameters
        if len(self.url_parameters) > 0:
            section = "collapseParameters"
            html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected URL parameters ({len(self.url_parameters)})
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
        
        # region form list

        if len(self.forms_list) > 0:
            section = "collapseForms"
            html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected Forms ({len(self.url_parameters)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>Method</th>
                                            <th>URL</th>
                                            <th>Origin URL</th>
                                            <th>parameter(s)</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            """

            for form in self.forms_list:
                html += f"""
                                        <tr>
                                            <td>{form['method'].upper()}</td>
                                            <td><a href="{form['url']}">{form['url']}</a></td>
                                            <td><a href="{form['origin_url']}">{form['origin_url']}</a></td>
                                            <td><ul>"""
                for param in form['parameters']:
                    html += f"<li>{param['name']}</li>"
                html += """                 </ul></td>
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
    
    # endregion

    # region Found vulnerabilities
    
    high_criticality = 0
    medium_criticality = 0
    low_criticality = 0

    high_criticality += len(self.found_sqli)
    high_criticality += len(self.found_fi)
    high_criticality += len(self.found_ssrf)
    high_criticality += len(self.found_credentials)

    medium_criticality += len(self.found_xss)

    low_criticality += len(self.found_openredirect)
    low_criticality += len(self.found_misconf)

    if self.attack_mode and high_criticality+medium_criticality+low_criticality > 0:

        html += """
            <h2 id="findings-reporting" style="margin-top: 50px;" class="mb-4">Findings and vulnerability reporting :</h2>
        """

        if high_criticality > 0:
            html += """
            <!-- High Section -->
            <section class="table-container">
                <h2 class="h4 mt-4" style="color: red;">High Criticality</h2>"""
    
            if len(self.found_sqli) > 0:
                section = "collapseSQLI"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected SQL injection ({len(self.found_sqli)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Method</th>
                                            <th>Parameter</th>
                                            <th>Type</th>
                                            <th>SQLMAP Payload</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,data in self.found_sqli:
                    url, method, parameter, name, name2, payload = data
                    html += f"""
                                        <tr>
                                            <td><a href="{url}">{url}</a></td>
                                            <td>{method.upper()}</td>
                                            <td>{parameter}</td>
                                            <td><ul><li>{name}</li><li>{name2}</li></ul></td>
                                            <td>{payload}</a></td>
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

            if len(self.found_credentials) > 0:
                section = "collapseDefCredentials"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected Default Credentials ({len(self.found_credentials)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Username</th>
                                            <th>Password</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,username,password in self.found_credentials:
                    html += f"""
                                        <tr>
                                            <td><a href="{url}">{url}</a></td>
                                            <td>{username}</td>
                                            <td>{password}</a></td>
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

            if len(self.found_fi) > 0:
                section = "collapseFI"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected LFI ({len(self.found_fi)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Username</th>
                                            <th>Password</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,method,payload in self.found_fi:
                    payload_url = url
                    if method.lower() == "get":
                        payload_url = url + payload
                    html += f"""
                                        <tr>
                                            <td><a href="{payload_url}">{url}</a></td>
                                            <td>{method.upper()}</td>
                                            <td>{payload}</a></td>
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

            if len(self.found_ssrf) > 0:
                section = "collapseSSRF"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected SSRF ({len(self.found_ssrf)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Method</th>
                                            <th>Parameter</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,method,parameters in self.found_ssrf:
                    html += f"""
                                        <tr>
                                            <td><a href="{url}">{url}</a></td>
                                            <td>{method.upper()}</td>
                                            <td>{",".join(parameters)}</a></td>
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
            
            html += """
            </section>
            """

        if medium_criticality > 0:
            html += """
            <!-- Medium Section -->
            <section class="table-container">
                <h2 class="h4 mt-4" style="color: orange;">Medium Criticality</h2>"""
    
            if len(self.found_xss) > 0:
                section = "collapseXSS"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected XSS ({len(self.found_xss)})
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
                                            <th>Parameter</th>
                                            <th>method</th>
                                            <th>Confidence</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,parameter,method,xss_type,confidence,payload in self.found_xss:
                    if confidence.lower() == "high":
                        if payload.find('src') != -1:
                            payload += '<img src=x onerror="alert(\'lincox\')">'
                    html += f"""
                                        <tr>
                                            <td>{xss_type}</td>
                                            <td><a href="{url}?{parameter}={escape(payload)}">{url}</a></td>
                                            <td>{parameter}</td>
                                            <td>{method.upper()}</td>
                                            <td>{confidence}</a></td>
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
            
            html += """
            </section>
            """

        if low_criticality > 0:
            html += """
            <!-- Low Section -->
            <section class="table-container">
                <h2 class="h4 mt-4" style="color: blue;">Low Criticality</h2>"""
    
            if len(self.found_openredirect) > 0:
                section = "collapseOpenRedirect"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Detected Open Redirect ({len(self.found_openredirect)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Parameter</th>
                                            <th>Method</th>
                                            <th>Type</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                for url,parameter,method,redirect_type in self.found_openredirect:
                    html += f"""
                                        <tr>
                                            <td><a href="{url}?{parameter}=//google.com/{url}">{url}</a></td>
                                            <td>{parameter}</td>
                                            <td>{method.upper()}</td>
                                            <td>{redirect_type}</a></td>
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

            if len(self.found_misconf) > 0:
                section = "collapseMisconf"
                html += f"""
                <div class="accordion">
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#{section}" aria-expanded="false" aria-controls="{section}">
                                View Misconfiguration ({len(self.found_misconf)})
                            </button>
                        </h2>
                        <div id="{section}" class="accordion-collapse collapse" aria-labelledby="headingURLs"
                            data-bs-parent="#urlsAccordion">
                            <div class="accordion-body">
                                <table class="table table-bordered table-striped">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>URL</th>
                                            <th>Type</th>
                                            <th>Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                """

                misconf_types = {
                    "missing_header": "Security Header Missing",
                    "bad_cookie": "A cookie doesn't use secure attributes",
                    "csrf_not_found": "Not CSRF found in a form",
                    "csrf_not_used": "A CSRF parameter is found but not used"
                }

                for misconf in self.found_misconf:
                    html += f"""
                                        <tr>
                                            <td><a href="{misconf['url']}">{misconf['url']}</a></td>
                                            <td>{misconf_types[misconf['type']]}</td>"""
                    if misconf["type"] == "missing_header":
                        html += f"""        <td><b>Missing header : {misconf['name']}.</b><br>{misconf['comments']}</td>"""
                    if misconf["type"] == "bad_cookie":
                        attrs = []
                        if not misconf['comments']['HttpOnly']:
                            attrs.append('HttpOnly')
                        if not misconf['comments']['Secure']:
                            attrs.append('Secure')
                        html += f"""        <td>Missing attributes on a cookie : {",".join(attrs)}</td>"""
                    if misconf["type"] == "csrf_not_found":
                        html += f"""        <td>Missing CSRF on {misconf['comments'].upper()} form</td>"""
                    if misconf["type"] == "csrf_not_used":
                        html += f"""        <td>CSRF found but not used on {misconf['comments'].upper()} form</td>"""

                    html +=                    """</tr>
                    """

                html += """
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                """


            html += """
            </section>
            """
    
    
    # endregion

    high_criticality = str(high_criticality)
    medium_criticality = str(medium_criticality)
    low_criticality = str(low_criticality)

    html += """
    </div>
    <script>
        // Column Chart Configuration
        const columnCtx = document.getElementById('columnChart').getContext('2d');
        const columnChart = new Chart(columnCtx, {
        type: 'bar',
        data: {
            labels: ['Number of findings'],
            datasets: [
            {
                label: 'misconfiguration',
                data: [""" + str(len(self.found_misconf)) + """],
                backgroundColor: 'blue',
            },
            {
                label: 'XSS',
                data: [""" + str(len(self.found_xss)) + """],
                backgroundColor: 'yellow',
            },
            {
                label: 'open redirect',
                data: [""" + str(len(self.found_openredirect)) +"""],
                backgroundColor: 'green',
            },
            {
                label: 'SSRF',
                data: [""" + str(len(self.found_ssrf)) + """],
                backgroundColor: 'pink',
            },
            {
                label: 'File Inclusion',
                data: [""" + str(len(self.found_fi)) + """],
                backgroundColor: 'purple',
            },
            {
                label: 'Default credentials',
                data: [""" + str(len(self.found_credentials)) + """],
                backgroundColor: 'orange',
            },
            {
                label: 'SQL injection',
                data: [""" + str(len(self.found_sqli)) + """],
                backgroundColor: 'red',
            },
            ]
        },
        options: {
            responsive: true,
            plugins: {
            legend: {
                display: true,
                position: 'top',
            },
            },
            scales: {
            x: {
                title: {
                display: false,
                text: '',
                },
            },
            y: {
                beginAtZero: true,
                title: {
                display: false,
                text: '',
                },
            },
            },
        }
        });

        // Pie Chart Configuration
        const pieCtx = document.getElementById('pieChart').getContext('2d');
        const pieChart = new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: ['Low', 'Medium', 'High'],
            datasets: [
            {
                data: [""" + ",".join([low_criticality,medium_criticality,high_criticality])  +"""],
                backgroundColor: ['blue', 'orange', 'red'],
            }
            ]
        },
        options: {
            responsive: true,
            plugins: {
            legend: {
                display: true,
                position: 'top',
            },
            },
        }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    return html
