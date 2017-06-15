<?php

header('Content-Type: application/json');

/**
 * Append a message to the the log file.
 * @param $message
 */
function writeLog($message)
{
    file_put_contents('local/log.log', $message . PHP_EOL, FILE_APPEND);
}

/**
 * Send a JSON response to the client and stop execution.
 * @param string[] $array The array that will be parsed to JSON.
 */
function response($array)
{
    echo json_encode($array);
    die();
}

if (!isset($_POST['nonce'], $_POST['signature'])) {
    writeLog('Parameter nonce or signature missing.');
    response([
        'error' => [
            'message' => 'Parameters `nonce` and `signature` are required',
        ],
    ]);
}

$nonce = $_POST['nonce'];
$signature = $_POST['signature'];

$access = json_decode(file_get_contents('local/access.json'), true);

if (!isset($access[$nonce])) {
    writeLog(sprintf('Non-existent nonce (%s) tried to gain access.', $nonce));
    response([
        'error' => [
            'Access denied',
        ],
    ]);
}

$nonceFile = tmpfile();
fwrite($nonceFile, $nonce);

$signatureFile = tmpfile();
fwrite($signatureFile, $signature);

ob_start();
passthru(sprintf('/usr/bin/python2.7 verify.py %s %s',
    stream_get_meta_data($nonceFile)['uri'],
    stream_get_meta_data($signatureFile)['uri']));

fclose($nonceFile);
fclose($signatureFile);

$output = ob_get_clean();
$output = json_decode($output, true);

if (isset($output['data']) && $output['data']['valid'] === true) {
    $username = $output['data']['username'];
    $fingerprint = $output['data']['fingerprint'];
    if ($access[$nonce]['fingerprint'] === $fingerprint) {
        writeLog(sprintf('Access granted to %s (%s)', $username, $fingerprint));
        response([
            'data' => [
                'message' => 'Access granted.',
            ],
        ]);
    } else {
        writeLog(sprintf('Access denied, the signature (by %s) was valid but the fingerprint(%s) of the used key
         does not match the fingerprint(%s) linked to the nonce(%s).',
            $username, $fingerprint, $access[$nonce]['fingerprint'], $nonce));
        response([
            'error' => [
                'message' => 'Access denied.',
            ],
        ]);
    }
} else {
    writeLog(sprintf('Access denied. Nonce: %s (%s)', $nonce, $output['error']['message']));
    response([
        'error' => [
            'message' => 'Access denied.',
        ],
    ]);
}
