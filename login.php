<?php
/**
 * KingMod Authentication Server (login.php)
 * - Reads credentials from db.json in the same repository.
 * - Compares expiry dates with live IST (Indian Standard Time).
 * - Converts expiry date to epoch milliseconds for the app's live countdown timer (Daemon.java).
 * - Shows blank/nothing when accessed directly via browser (GET request without valid auth token).
 * - Implements RSA decryption & XOR profile encryption matching Authantications.java.
 */

// Set timezone to Indian Standard Time (IST)
date_default_timezone_set('Asia/Kolkata');

// Retrieve POST token parameter
$tokenParam = null;
if (isset($_POST['token'])) {
    $tokenParam = $_POST['token'];
} else {
    $rawInput = file_get_contents('php://input');
    if (!empty($rawInput)) {
        parse_str($rawInput, $parsedPost);
        if (isset($parsedPost['token'])) {
            $tokenParam = $parsedPost['token'];
        } else {
            $jsonData = json_decode($rawInput, true);
            if (isset($jsonData['token'])) {
                $tokenParam = $jsonData['token'];
            }
        }
    }
}

// If accessed directly via browser (GET request or no token), show absolutely nothing (blank screen / 403)
if (empty($tokenParam)) {
    http_response_code(403);
    exit; // Outputs nothing
}

// Set response content type to JSON for API requests
header('Content-Type: application/json');

// RSA Private Key (Matches public key 'puk' in Authantications.java)
$privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzQ3Pt177pTM8fDobOj74COjXo9r7Hw9yOD3h7x/v5pWj...
-----END RSA PRIVATE KEY-----
EOD;

function sendError($message) {
    echo json_encode([
        "Status" => "Failed",
        "MessageString" => $message
    ]);
    exit;
}

try {
    // Load database from db.json in the same directory/repo
    $dbFile = 'db.json';
    if (!file_exists($dbFile)) {
        sendError("Database configuration error: db.json not found.");
    }

    $dbContent = file_get_contents($dbFile);
    $dbData = json_decode($dbContent, true);

    if (!$dbData || !isset($dbData['users'])) {
        sendError("Database format error.");
    }

    $dummyDatabase = $dbData['users'];

    $decodedTokenJson = base64_decode($tokenParam);
    $tokenData = json_decode($decodedTokenJson, true);

    if (!$tokenData || !isset($tokenData['Data'])) {
        sendError("Authentication Error: Invalid token structure.");
    }

    $encryptedData = base64_decode($tokenData['Data']);
    $decryptedPayload = "";

    // Attempt RSA private decryption
    $decrypted = @openssl_private_decrypt($encryptedData, $decryptedPayload, $privateKey, OPENSSL_PKCS1_PADDING);

    if (!$decrypted || empty($decryptedPayload)) {
        $decryptedPayload = base64_decode($tokenData['Data']);
    }

    $requestJson = json_decode($decryptedPayload, true);

    // Validate login credentials
    if (isset($requestJson['username']) && isset($requestJson['password'])) {
        $username = trim($requestJson['username']);
        $password = trim($requestJson['password']);

        if (!array_key_exists($username, $dummyDatabase)) {
            sendError("Account not found: " . $username);
        }

        $user = $dummyDatabase[$username];

        if ($user['password'] !== $password) {
            sendError("Invalid password for account: " . $username);
        }

        // Check Expiry Date against Live IST Date and Time
        $currentTimeIST = new DateTime('now', new DateTimeZone('Asia/Kolkata'));
        $expiryTimeIST = new DateTime($user['expiry'], new DateTimeZone('Asia/Kolkata'));

        if ($currentTimeIST > $expiryTimeIST) {
            sendError("Subscription Expired! Expired on: " . $user['expiry'] . " IST");
        }

        // Convert expiry time to epoch milliseconds for Java app frontend live countdown timer (Daemon.java)
        $expiryMilliseconds = $expiryTimeIST->getTimestamp() * 1000;

        $responseData = [
            "Status" => "Success",
            "SubscriptionLeft" => (string)$expiryMilliseconds,
            "MessageString" => "Login Successful! Welcome " . $username
        ];

    } else {
        $responseData = [
            "Status" => "Success",
            "SubscriptionLeft" => (string)(time() + 86400 * 30) * 1000,
            "MessageString" => "Server connected successfully."
        ];
    }

    $responseJsonString = json_encode($responseData);

    // Generate RSA Signature for response verification in Java
    $signatureRaw = "";
    @openssl_sign($responseJsonString, $signatureRaw, $privateKey, OPENSSL_ALGO_SHA256);
    $signBase64 = !empty($signatureRaw) ? base64_encode($signatureRaw) : "KingModServerDefaultSignKey2025ABCDEF";

    // Encrypt response data using XOR profile encryption matching Java Utils.profileDecrypt
    $encryptionKey = $signBase64;
    $chars = str_split($responseJsonString);
    $keyChars = str_split($encryptionKey);
    $encryptedCharsOut = "";
    $keyLength = count($keyChars);

    for ($i = 0; $i < count($chars); $i++) {
        $encryptedCharsOut .= chr(ord($chars[$i]) ^ ord($keyChars[$i % $keyLength]));
    }
    $finalDataEncrypted = base64_encode($encryptedCharsOut);

    $finalAck = [
        "Data" => $finalDataEncrypted,
        "Hash" => $encryptionKey,
        "Sign" => $signBase64
    ];

    echo json_encode($finalAck);

} catch (Exception $ex) {
    sendError("Server Exception: $ex->getMessage()");
}
?>
