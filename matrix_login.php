<?php
// Included in login.php

// Only start a session to check if they have a cookie that looks like our session
$server_name = strtok($_SERVER['HTTP_HOST'],":");
if (!empty($_COOKIE['unraid_'.md5($server_name)])) {
    // Start the session so we can check if $_SESSION has data
    if (session_status()==PHP_SESSION_NONE) session_start();

    // Check if the user is already logged in
    if ($_SESSION && !empty($_SESSION['unraid_user'])) {
        // Redirect the user to the start page
        header("Location: /".$start_page);
        exit;
    }
}

function readFromFile($file): string {
    $text = "";
    if (file_exists($file) && filesize($file) > 0) {
        $fp = fopen($file,"r");
        if (flock($fp, LOCK_EX)) {
            $text = fread($fp, filesize($file));
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
    return $text;
}

function appendToFile($file, $text): void {
    $fp = fopen($file,"a");
    if (flock($fp, LOCK_EX)) {
        fwrite($fp, $text);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

function writeToFile($file, $text): void {
    $fp = fopen($file,"w");
    if (flock($fp, LOCK_EX)) {
        fwrite($fp, $text);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

// Source: https://stackoverflow.com/a/2524761
function isValidTimeStamp($timestamp)
{
    return ((string) (int) $timestamp === $timestamp)
        && ($timestamp <= PHP_INT_MAX)
        && ($timestamp >= ~PHP_INT_MAX);
}

function cleanupFails(string $failFile, int $time): int {
    global $cooldown;

    // Read existing fails
    @mkdir(dirname($failFile), 0755);
    $failText = readFromFile($failFile);
    $fails = explode("\n", trim($failText));

    // Remove entries older than $cooldown minutes, and entries that are not timestamps
    $updateFails = false;
    foreach ((array) $fails as $key => $value) {
        if ( !isValidTimeStamp($value) || ($time - $value > $cooldown) || ($value > $time) ) {
            unset ($fails[$key]);
            $updateFails = true;
        }
    }

    // Save fails to disk
    if ($updateFails) {
        $failText = implode("\n", $fails)."\n";
        writeToFile($failFile, $failText);
    }
    return count($fails);
}

function verifyUsernamePassword(string $username, string $password): bool {
    if ($username != "root") return false;

    $output = exec("/usr/bin/getent shadow $username");
    if ($output === false) return false;
    $credentials = explode(":", $output);
    return password_verify($password, $credentials[1]);
}

function verifyTwoFactorToken(string $username, string $token): bool {
    try {
        // Create curl client
        $curlClient = curl_init();
        curl_setopt($curlClient, CURLOPT_HEADER, true);
        curl_setopt($curlClient, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curlClient, CURLOPT_UNIX_SOCKET_PATH, '/var/run/unraid-api.sock');
        curl_setopt($curlClient, CURLOPT_URL, 'http://unixsocket/verify');
        curl_setopt($curlClient, CURLOPT_BUFFERSIZE, 256);
        curl_setopt($curlClient, CURLOPT_TIMEOUT, 5);
        curl_setopt($curlClient, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Origin: /var/run/unraid-notifications.sock'));
        curl_setopt($curlClient, CURLOPT_POSTFIELDS, json_encode([
            'username' => $username,
            'token' => $token
        ]));

        // Send the request
        curl_exec($curlClient);

        // Get the http status code
        $httpCode = curl_getinfo($curlClient, CURLINFO_HTTP_CODE);

        // Close the connection
        curl_close($curlClient);

        // Error
        // This should accept 200 or 204 status codes
        if ($httpCode !== 200 && $httpCode !== 204) {
            // Log error to syslog
            exec("logger -t webGUI ".escapeshellarg("2FA code for {$username} is invalid, blocking access!"));
            return false;
        }

        // Log success to syslog
        exec("logger -t webGUI ".escapeshellarg("2FA code for {$username} is valid, allowing login!"));

        // Success
        return true;
    } catch (Exception $exception) {
        // Error
        return false;
    }
}

// Check if a haystack ends in a needle
function endsWith($haystack, $needle): bool {
    return substr_compare($haystack, $needle, -strlen($needle)) === 0;
}

// Check if we're accessing this via a wildcard cert
function isWildcardCert(): bool {
    global $server_name;
    return endsWith($server_name, '.myunraid.net');
}

// Check if we're accessing this locally via the expected myunraid.net url
function isLocalAccess(): bool {
    global $nginx, $server_name;
    return isWildcardCert() && $nginx['NGINX_LANFQDN'] === $server_name;
}

// Check if we're accessing this remotely via the expected myunraid.net url
function isRemoteAccess(): bool {
    global $nginx, $server_name;
    return isWildcardCert() && $nginx['NGINX_WANFQDN'] === $server_name;
}

// Check if 2fa is enabled for local (requires USE_SSL to be "auto" so no alternate urls can access the server)
function isLocalTwoFactorEnabled(): bool {
    global $nginx, $my_servers;
    return $nginx['NGINX_USESSL'] === "auto" && ($my_servers['local']['2Fa']??'') === 'yes';
}

// Check if 2fa is enabled for remote
function isRemoteTwoFactorEnabled(): bool {
    global $my_servers;
    return ($my_servers['remote']['2Fa']??'') === 'yes';
}

// Load configs into memory
$my_servers = @parse_ini_file('/boot/config/plugins/dynamix.my.servers/myservers.cfg', true);
$nginx = @parse_ini_file('/var/local/emhttp/nginx.ini');

// Vars
$maxFails = 3;
$cooldown = 15 * 60; // 15 mins
$remote_addr = $_SERVER['REMOTE_ADDR'] ?? "unknown";
$failFile = "/var/log/pwfail/{$remote_addr}";

// Get the credentials
$username = $_POST['username']??'';
$password = $_POST['password']??'';
$token = $_REQUEST['token']??'';

// Check if we need 2fa
$twoFactorRequired = (isLocalAccess() && isLocalTwoFactorEnabled()) || (isRemoteAccess() && isRemoteTwoFactorEnabled());

// If we have a username + password combo attempt to login
if (!empty($username) && !empty($password)) {
    try {
        // Bail if we're missing the 2FA token and we expect one
        if (isWildcardCert() && $twoFactorRequired && empty($token)) throw new Exception(_('No 2FA token detected'));

        // Read existing fails, cleanup expired ones
        $time = time();
        $failCount = cleanupFails($failFile, $time);

        // Check if we're limited
        if ($failCount >= $maxFails) {
            if ($failCount == $maxFails) exec("logger -t webGUI ".escapeshellarg("Ignoring login attempts for {$username} from {$remote_addr}"));
            throw new Exception(_('Too many invalid login attempts'));
        }

        // Bail if username + password combo doesn't work
        if (!verifyUsernamePassword($username, $password)) throw new Exception(_('Invalid username or password'));

        // Bail if we need a token but it's invalid
        if (isWildcardCert() && $twoFactorRequired && !verifyTwoFactorToken($username, $token)) throw new Exception(_('Invalid 2FA token'));

        // Successful login, start session
        @unlink($failFile);
        if (session_status()==PHP_SESSION_NONE) session_start();
        $_SESSION['unraid_login'] = time();
        $_SESSION['unraid_user'] = $username;
        session_regenerate_id(true);
        session_write_close();
        exec("logger -t webGUI ".escapeshellarg("Successful login user {$username} from {$remote_addr}"));

        // Redirect the user to the start page
        header("Location: /".$start_page);
        exit;
    } catch (Exception $exception) {
        // Set error message
        $error = $exception->getMessage();

        // Log error to syslog
        exec("logger -t webGUI ".escapeshellarg("Unsuccessful login user {$username} from {$remote_addr}"));
        appendToFile($failFile, $time."\n");
    }
}

$boot   = "/boot/config/plugins/dynamix";
$myFile = "case-model.cfg";
$myCase = file_exists("$boot/$myFile") ? file_get_contents("$boot/$myFile") : false;

extract(parse_plugin_cfg('dynamix', true));
$theme_dark = in_array($display['theme'], ['black', 'gray']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <meta http-equiv="Content-Security-Policy" content="block-all-mixed-content">
    <meta name="referrer" content="same-origin">
    <title><?=$var['NAME']?>/Login</title>
    <style>
    @font-face{font-family:clear-sans;font-weight:normal;font-style:normal; src:url('/webGui/styles/clear-sans.woff?v=20220513') format('woff')}
    @font-face{font-family:clear-sans;font-weight:bold;font-style:normal; src:url('/webGui/styles/clear-sans-bold.woff?v=20220513') format('woff')}
    @font-face{font-family:clear-sans;font-weight:normal;font-style:italic; src:url('/webGui/styles/clear-sans-italic.woff?v=20220513') format('woff')}
    @font-face{font-family:clear-sans;font-weight:bold;font-style:italic; src:url('/webGui/styles/clear-sans-bold-italic.woff?v=20220513') format('woff')}
    @font-face{font-family:bitstream;font-weight:normal;font-style:normal; src:url('/webGui/styles/bitstream.woff?v=20220513') format('woff')}
    @font-face{font-family:bitstream;font-weight:bold;font-style:normal; src:url('/webGui/styles/bitstream-bold.woff?v=20220513') format('woff')}
    @font-face{font-family:bitstream;font-weight:normal;font-style:italic; src:url('/webGui/styles/bitstream-italic.woff?v=20220513') format('woff')}
    @font-face{font-family:bitstream;font-weight:bold;font-style:italic; src:url('/webGui/styles/bitstream-bold-italic.woff?v=20220513') format('woff')}

    *, *::before, *::after { box-sizing: border-box; }

    body {
        background: #000;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        overflow: hidden;
    }

    /* ── Matrix canvas ── */
    #matrix-canvas {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0;
        pointer-events: none;
    }

    /* ── CRT scanlines — static horizontal lines ── */
    .scanlines {
        position: fixed;
        inset: 0;
        background: repeating-linear-gradient(
            to bottom,
            transparent 0px,
            transparent 2px,
            rgba(0, 0, 0, 0.15) 2px,
            rgba(0, 0, 0, 0.15) 4px
        );
        pointer-events: none;
        z-index: 5;
    }

    /* ── CRT edge glow ── */
    .crt-glow {
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse at center,
            rgba(0, 255, 65, 0.04) 0%,
            rgba(0, 0, 0, 0.5) 80%
        );
        box-shadow: inset 0 0 80px rgba(0, 255, 65, 0.12);
        pointer-events: none;
        z-index: 6;
    }

    /* ── Vignette ── */
    .vignette {
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse at center,
            transparent 45%,
            rgba(0, 0, 0, 0.75) 100%
        );
        pointer-events: none;
        z-index: 6;
    }

    /* ── Login box ── */
    #login {
        position: relative;
        z-index: 10;
        background: rgba(0, 0, 0, 0.85);
        border: 1px solid #00ff41;
        border-radius: 10px;
        box-shadow: 0 0 24px rgba(0, 255, 65, 0.35), inset 0 0 30px rgba(0, 255, 65, 0.03);
        padding: 2.5rem 2rem 2rem;
        width: 360px;
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    h1 {
        font-size: 1.8rem;
        font-weight: bold;
        text-align: center;
        color: #00ff41;
        text-shadow: 0 0 6px #00ff41, 0 0 18px #00ff41, 0 0 36px #00a328;
        margin: 0 0 0.25rem;
        letter-spacing: 0.04em;
    }

    h2 {
        font-size: 0.78rem;
        font-weight: normal;
        text-align: center;
        color: rgba(0, 255, 65, 0.45);
        margin: 0 0 1.5rem;
        letter-spacing: 0.16em;
        text-transform: uppercase;
    }

    .form {
        width: 100%;
        display: flex;
        flex-direction: column;
    }

    input[type="text"],
    input[type="password"] {
        width: 100%;
        background: rgba(0, 8, 0, 0.75);
        color: #00ff41;
        border: 1px solid rgba(0, 255, 65, 0.35);
        border-radius: 5px;
        padding: 0.65rem 0.9rem;
        margin-bottom: 0.85rem;
        font-size: 0.95rem;
        font-family: 'Courier New', monospace;
        transition: border-color 0.2s, box-shadow 0.2s;
    }

    input[type="text"]:focus,
    input[type="password"]:focus {
        outline: none;
        border-color: #00ff41;
        box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
    }

    input[type="text"]::placeholder,
    input[type="password"]::placeholder {
        color: rgba(0, 255, 65, 0.28);
    }

    .button, .button--small {
        width: 100%;
        background: transparent;
        color: #00ff41;
        border: 1px solid #00ff41;
        border-radius: 5px;
        padding: 0.65rem 1rem;
        font-size: 0.82rem;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        cursor: pointer;
        transition: background 0.2s, color 0.2s, box-shadow 0.2s;
        margin-top: 0.2rem;
    }

    .button:hover, .button--small:hover {
        background: #00ff41;
        color: #000;
        box-shadow: 0 0 16px rgba(0, 255, 65, 0.45);
    }

    .error {
        color: #ff4444;
        text-align: center;
        font-size: 0.82rem;
        margin-bottom: 0.75rem;
        text-shadow: 0 0 6px rgba(255, 68, 68, 0.4);
    }

    a {
        color: rgba(0, 255, 65, 0.45);
        text-decoration: none;
        font-size: 0.75rem;
        letter-spacing: 0.04em;
        transition: color 0.2s;
    }
    a:hover { color: #00ff41; }

    .js-removeTimeout a { display: block; text-align: center; margin-top: 1.25rem; }

    .hidden { display: none; }

    [class^="case-"], [class*=" case-"] {
        font-family: 'cases' !important;
        speak: none;
        font-style: normal;
        font-weight: normal;
        font-variant: normal;
        text-transform: none;
        line-height: 1;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }

    @media (max-width: 500px) {
        #login { width: 90%; padding: 1.75rem 1.25rem; }
        h1 { font-size: 1.4rem; }
    }
    </style>
    <link type="text/css" rel="stylesheet" href="<?autov("/webGui/styles/default-cases.css")?>">
    <link type="image/png" rel="shortcut icon" href="/webGui/images/<?=$var['mdColor']?>.png">
</head>

<body>
    <canvas id="matrix-canvas"></canvas>
    <div class="scanlines"></div>
    <div class="crt-glow"></div>
    <div class="vignette"></div>

    <section id="login">
        <h1><?=htmlspecialchars($var['NAME'])?></h1>
        <h2>Access Terminal</h2>

        <div class="form">
            <form class="js-removeTimeout" action="/login" method="POST">
                <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>
                    <p>
                        <input name="username" type="text" placeholder="<?=_('Username')?>" autocapitalize="none" autocomplete="off" spellcheck="false" autofocus required>
                        <input name="password" type="password" placeholder="<?=_('Password')?>" required>
                        <? if ($twoFactorRequired && !empty($token)) { ?>
                        <input name="token" type="hidden" value="<?= $token ?>">
                        <? } ?>
                    </p>
                    <? if ($error) echo "<p class='error'>$error</p>"; ?>
                    <p>
                        <button type="submit" class="button button--small"><?=_('Login')?></button>
                    </p>
                <? } else { ?>
                    <? if ($error) { ?>
                        <div><p class="error" style="padding-top:10px;"><?= $error ?></p></div>
                    <? } else { ?>
                        <div><p class="error" style="padding-top:10px;" title="<?= _('Please access this server via the My Servers Dashboard') ?>"><?= _('No 2FA token detected') ?></p></div>
                    <? } ?>
                    <div>
                        <a href="https://forums.unraid.net/my-servers/" class="button button--small" title="<?=_('Go to My Servers Dashboard')?>"><?=_('Go to My Servers Dashboard')?></a>
                    </div>
                <? } ?>
                <script type="text/javascript">
                    document.cookie = "cookietest=1";
                    cookieEnabled = document.cookie.indexOf("cookietest=")!=-1;
                    document.cookie = "cookietest=1; expires=Thu, 01-Jan-1970 00:00:01 GMT";
                    if (!cookieEnabled) {
                        const errorElement = document.createElement('p');
                        errorElement.classList.add('error');
                        errorElement.textContent = "<?=_('Please enable cookies to use the Unraid webGUI')?>";
                        document.body.textContent = '';
                        document.body.appendChild(errorElement);
                    }
                </script>
            </form>

            <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>
                <div class="js-addTimeout hidden">
                    <p class="error" style="padding-top:10px;"><?=_('Transparent 2FA Token timed out')?></p>
                    <a href="https://forums.unraid.net/my-servers/" class="button button--small" title="<?=_('Go to My Servers Dashboard')?>"><?=_('Go to My Servers Dashboard')?></a>
                </div>
            <? } ?>
        </div>

        <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>
            <p class="js-removeTimeout"><a href="https://docs.unraid.net/go/lost-root-password/" target="_blank"><?=_('Password recovery')?></a></p>
        <? } ?>
    </section>

    <? if ($twoFactorRequired && !empty($token)) { ?>
        <script type="text/javascript">
            const $elsToRemove = document.querySelectorAll('.js-removeTimeout');
            const $elsToShow = document.querySelectorAll('.js-addTimeout');
            const tokenName = '<?=$token?>'.slice(-20);
            const ts = Date.now();
            const timeoutStarted = sessionStorage.getItem(tokenName) ? Number(sessionStorage.getItem(tokenName)) : ts;
            const timeoutDiff = ts - timeoutStarted;
            const timeoutMS = 297000 - timeoutDiff;
            sessionStorage.setItem(tokenName, timeoutStarted);
            const tokenTimeout = setTimeout(() => {
                $elsToRemove.forEach(z => z.remove());
                $elsToShow.forEach(z => z.classList.remove('hidden'));
            }, timeoutMS);
        </script>
    <? } ?>

    <script>
    (function () {
        const canvas = document.getElementById('matrix-canvas');
        const ctx    = canvas.getContext('2d');

        // Extended katakana half-width + latin + symbols
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
                      'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝﾞﾟ' +
                      '@#$%&:<>/\\|{}[]';

        const fontSize = 16;
        let columns, drops;

        function init() {
            canvas.width  = window.innerWidth;
            canvas.height = window.innerHeight;
            columns = Math.floor(canvas.width / fontSize);
            // Stagger so columns don't all start at the same time
            drops = Array.from({ length: columns }, () =>
                Math.floor(Math.random() * -(canvas.height / fontSize))
            );
        }

        function draw() {
            // Semi-transparent fill creates the fading trail effect
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = `${fontSize}px monospace`;

            for (let i = 0; i < drops.length; i++) {
                const char = chars[Math.floor(Math.random() * chars.length)];
                const x = i * fontSize;
                const y = drops[i] * fontSize;

                if (y >= 0 && y <= canvas.height) {
                    // Bright near-white head — trail fades to green naturally via the fill overlay
                    ctx.fillStyle = '#ccffcc';
                    ctx.fillText(char, x, y);
                }

                if (y > canvas.height && Math.random() > 0.975) {
                    drops[i] = Math.floor(Math.random() * -40);
                }
                drops[i]++;
            }

            requestAnimationFrame(draw);
        }

        init();
        draw();
        window.addEventListener('resize', init);
    })();
    </script>
</body>
</html>
