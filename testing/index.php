<!DOCTYPE html>
<html>
<head>
    <title>SSRF Vulnerable Page</title>
</head>
<body>

<h1>SSRF Test</h1>

<form method="POST">
    URL to fetch: <input type="text" name="url" value="http://127.0.0.1"><br>
    <input type="submit" value="Fetch URL">
</form>

<?php

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $url_to_fetch = $_POST['url'];

    // Very weak validation (DO NOT USE IN PRODUCTION)
    if (empty($url_to_fetch)) {
        echo "<p style='color:red;'>Please enter a URL.</p>";
    } else {
        try {
          //using curl is more secure than file_get_contents
            $ch = curl_init($url_to_fetch);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Set a timeout to prevent hanging
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS); // Restrict protocols to HTTP/HTTPS
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS); // Restrict redirect protocols to HTTP/HTTPS
            $response = curl_exec($ch);
            if(curl_errno($ch)){
              throw new Exception(curl_error($ch));
            }
            curl_close($ch);

            if ($response === false) {
                throw new Exception("Failed to fetch URL.");
            }

            echo "<h2>Response:</h2>";
            echo "<pre>" . htmlspecialchars($response) . "</pre>"; // Sanitize output!

        } catch (Exception $e) {
            echo "<p style='color:red;'>Error: " . htmlspecialchars($e->getMessage()) . "</p>";
        }
    }
}
?>

</body>
</html>
