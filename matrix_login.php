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

        curl_exec($curlClient);
        $httpCode = curl_getinfo($curlClient, CURLINFO_HTTP_CODE);
        curl_close($curlClient);

        if ($httpCode !== 200 && $httpCode !== 204) {
            exec("logger -t webGUI ".escapeshellarg("2FA code for {$username} is invalid, blocking access!"));
            return false;
        }

        exec("logger -t webGUI ".escapeshellarg("2FA code for {$username} is valid, allowing login!"));
        return true;
    } catch (Exception $exception) {
        return false;
    }
}

function endsWith($haystack, $needle): bool {
    return substr_compare($haystack, $needle, -strlen($needle)) === 0;
}

function isWildcardCert(): bool {
    global $server_name;
    return endsWith($server_name, '.myunraid.net');
}

function isLocalAccess(): bool {
    global $nginx, $server_name;
    return isWildcardCert() && $nginx['NGINX_LANFQDN'] === $server_name;
}

function isRemoteAccess(): bool {
    global $nginx, $server_name;
    return isWildcardCert() && $nginx['NGINX_WANFQDN'] === $server_name;
}

function isLocalTwoFactorEnabled(): bool {
    global $nginx, $my_servers;
    return $nginx['NGINX_USESSL'] === "auto" && ($my_servers['local']['2Fa']??'') === 'yes';
}

function isRemoteTwoFactorEnabled(): bool {
    global $my_servers;
    return ($my_servers['remote']['2Fa']??'') === 'yes';
}

$my_servers = @parse_ini_file('/boot/config/plugins/dynamix.my.servers/myservers.cfg', true);
$nginx = @parse_ini_file('/var/local/emhttp/nginx.ini');

$maxFails = 3;
$cooldown = 15 * 60;
$remote_addr = $_SERVER['REMOTE_ADDR'] ?? "unknown";
$failFile = "/var/log/pwfail/{$remote_addr}";

$username = $_POST['username']??'';
$password = $_POST['password']??'';
$token = $_REQUEST['token']??'';

$twoFactorRequired = (isLocalAccess() && isLocalTwoFactorEnabled()) || (isRemoteAccess() && isRemoteTwoFactorEnabled());

if (!empty($username) && !empty($password)) {
    try {
        if (isWildcardCert() && $twoFactorRequired && empty($token)) throw new Exception(_('No 2FA token detected'));

        $time = time();
        $failCount = cleanupFails($failFile, $time);

        if ($failCount >= $maxFails) {
            if ($failCount == $maxFails) exec("logger -t webGUI ".escapeshellarg("Ignoring login attempts for {$username} from {$remote_addr}"));
            throw new Exception(_('Too many invalid login attempts'));
        }

        if (!verifyUsernamePassword($username, $password)) throw new Exception(_('Invalid username or password'));

        if (isWildcardCert() && $twoFactorRequired && !verifyTwoFactorToken($username, $token)) throw new Exception(_('Invalid 2FA token'));

        @unlink($failFile);
        if (session_status()==PHP_SESSION_NONE) session_start();
        $_SESSION['unraid_login'] = time();
        $_SESSION['unraid_user'] = $username;
        session_regenerate_id(true);
        session_write_close();
        exec("logger -t webGUI ".escapeshellarg("Successful login user {$username} from {$remote_addr}"));

        header("Location: /".$start_page);
        exit;
    } catch (Exception $exception) {
        $error = $exception->getMessage();
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
        inset: 0;
        width: 100%; height: 100%;
        z-index: 0;
        pointer-events: none;
    }

    /* ── CRT scanlines ── */
    .scanlines {
        position: fixed;
        inset: 0;
        background: repeating-linear-gradient(
            to bottom,
            transparent 0px, transparent 2px,
            rgba(0, 0, 0, 0.13) 2px, rgba(0, 0, 0, 0.13) 4px
        );
        pointer-events: none;
        z-index: 5;
    }

    /* ── CRT edge glow ── */
    .crt-glow {
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse at center, rgba(0,255,65,0.04) 0%, rgba(0,0,0,0.5) 80%);
        box-shadow: inset 0 0 80px rgba(0,255,65,0.1);
        pointer-events: none;
        z-index: 6;
    }

    /* ── Vignette ── */
    .vignette {
        position: fixed;
        inset: 0;
        background: radial-gradient(ellipse at center, transparent 40%, rgba(0,0,0,0.8) 100%);
        pointer-events: none;
        z-index: 6;
    }

    /* ── Login box ── */
    @keyframes borderPulse {
        0%, 100% { box-shadow: 0 0 18px rgba(0,255,65,0.3), inset 0 0 18px rgba(0,255,65,0.02); }
        50%       { box-shadow: 0 0 38px rgba(0,255,65,0.55), inset 0 0 28px rgba(0,255,65,0.05); }
    }

    #login {
        position: relative;
        z-index: 10;
        background: rgba(0, 4, 0, 0.92);
        border: 1px solid rgba(0, 255, 65, 0.6);
        border-radius: 8px;
        width: 380px;
        display: flex;
        flex-direction: column;
        animation: borderPulse 4s ease-in-out infinite;
        overflow: hidden;
    }

    /* ── Terminal chrome header ── */
    .term-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.55rem 0.9rem;
        background: rgba(0, 255, 65, 0.06);
        border-bottom: 1px solid rgba(0, 255, 65, 0.15);
        user-select: none;
    }

    .term-dots {
        display: flex;
        gap: 5px;
    }

    .term-dot {
        width: 9px;
        height: 9px;
        border-radius: 50%;
        border: 1px solid rgba(0, 255, 65, 0.4);
        background: rgba(0, 255, 65, 0.15);
    }

    .term-dot:first-child { background: rgba(0, 255, 65, 0.5); border-color: rgba(0,255,65,0.7); }

    .term-title {
        margin-left: auto;
        font-size: 0.6rem;
        letter-spacing: 0.18em;
        color: rgba(0, 255, 65, 0.35);
        text-transform: uppercase;
    }

    /* ── Login body ── */
    .login-body {
        padding: 1.75rem 1.75rem 1.5rem;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0;
    }

    h1 {
        font-size: 1.65rem;
        font-weight: bold;
        text-align: center;
        color: #00ff41;
        text-shadow: 0 0 8px #00ff41, 0 0 20px #00ff41, 0 0 40px #007a1f;
        margin: 0 0 0.2rem;
        letter-spacing: 0.06em;
    }

    .subtitle {
        font-size: 0.68rem;
        color: rgba(0, 255, 65, 0.4);
        letter-spacing: 0.22em;
        text-transform: uppercase;
        margin-bottom: 1.6rem;
        min-height: 1em;
    }

    .subtitle-cursor {
        display: inline-block;
        width: 7px;
        height: 0.75em;
        background: rgba(0, 255, 65, 0.6);
        margin-left: 1px;
        vertical-align: middle;
        animation: blink 1s step-end infinite;
    }

    @keyframes blink {
        0%, 100% { opacity: 1; }
        50%       { opacity: 0; }
    }

    /* ── Form ── */
    .form { width: 100%; display: flex; flex-direction: column; }

    .field-label {
        font-size: 0.6rem;
        letter-spacing: 0.2em;
        color: rgba(0, 255, 65, 0.4);
        text-transform: uppercase;
        margin-bottom: 0.35rem;
    }

    .input-row {
        display: flex;
        align-items: center;
        background: rgba(0, 12, 0, 0.8);
        border: 1px solid rgba(0, 255, 65, 0.25);
        border-radius: 4px;
        padding: 0 0.75rem;
        margin-bottom: 1rem;
        transition: border-color 0.2s, box-shadow 0.2s;
    }

    .input-row:focus-within {
        border-color: rgba(0, 255, 65, 0.8);
        box-shadow: 0 0 12px rgba(0, 255, 65, 0.2);
    }

    .input-prompt {
        color: rgba(0, 255, 65, 0.5);
        font-size: 0.9rem;
        padding-right: 0.5rem;
        user-select: none;
        flex-shrink: 0;
    }

    .input-row input {
        flex: 1;
        background: transparent;
        border: none;
        outline: none;
        color: #00ff41;
        font-family: 'Courier New', monospace;
        font-size: 0.92rem;
        padding: 0.6rem 0;
        caret-color: #00ff41;
    }

    .input-row input::placeholder { color: rgba(0, 255, 65, 0.2); }

    /* ── Button ── */
    .btn-wrap { width: 100%; margin-top: 0.5rem; }

    .button, .button--small {
        width: 100%;
        background: transparent;
        color: #00ff41;
        border: 1px solid rgba(0, 255, 65, 0.6);
        border-radius: 4px;
        padding: 0.7rem 1rem;
        font-size: 0.78rem;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        letter-spacing: 0.22em;
        text-transform: uppercase;
        text-align: center;
        text-decoration: none;
        display: block;
        cursor: pointer;
        transition: background 0.2s, color 0.2s, box-shadow 0.2s, border-color 0.2s;
        position: relative;
        overflow: hidden;
    }

    .button::before, .button--small::before {
        content: '';
        position: absolute;
        inset: 0;
        background: linear-gradient(90deg, transparent, rgba(0,255,65,0.08), transparent);
        transform: translateX(-100%);
        transition: transform 0.4s ease;
    }

    .button:hover::before, .button--small:hover::before {
        transform: translateX(100%);
    }

    .button:hover, .button--small:hover {
        background: rgba(0, 255, 65, 0.12);
        border-color: #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        color: #00ff41;
    }

    /* ── Error ── */
    .error {
        color: #ff4444;
        font-size: 0.78rem;
        margin-bottom: 0.75rem;
        padding: 0.5rem 0.75rem;
        background: rgba(255, 68, 68, 0.07);
        border: 1px solid rgba(255, 68, 68, 0.25);
        border-radius: 4px;
        text-align: center;
        text-shadow: 0 0 8px rgba(255,68,68,0.4);
        letter-spacing: 0.04em;
    }

    /* ── Status bar ── */
    .status-bar {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 1.25rem;
        padding-top: 0.85rem;
        border-top: 1px solid rgba(0, 255, 65, 0.1);
        font-size: 0.58rem;
        color: rgba(0, 255, 65, 0.28);
        letter-spacing: 0.1em;
        text-transform: uppercase;
        width: 100%;
    }

    .status-led {
        width: 5px;
        height: 5px;
        border-radius: 50%;
        background: #00ff41;
        flex-shrink: 0;
        animation: ledBlink 2.5s ease-in-out infinite;
    }

    @keyframes ledBlink {
        0%, 85%, 100% { opacity: 1; box-shadow: 0 0 4px #00ff41; }
        90%            { opacity: 0.2; box-shadow: none; }
    }

    /* ── Recovery link ── */
    .recovery {
        display: block;
        text-align: center;
        margin-top: 0.9rem;
        font-size: 0.65rem;
        color: rgba(0, 255, 65, 0.28);
        text-decoration: none;
        letter-spacing: 0.06em;
        transition: color 0.2s;
    }
    .recovery:hover { color: rgba(0, 255, 65, 0.7); }

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
        #login { width: 92%; }
        .login-body { padding: 1.5rem 1.25rem 1.25rem; }
        h1 { font-size: 1.35rem; }
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

        <!-- Terminal chrome bar -->
        <div class="term-header">
            <div class="term-dots">
                <div class="term-dot"></div>
                <div class="term-dot"></div>
                <div class="term-dot"></div>
            </div>
            <span class="term-title">matrix terminal &mdash; ssh session</span>
        </div>

        <div class="login-body">
            <h1><?=htmlspecialchars($var['NAME'])?></h1>
            <div class="subtitle" id="subtitle"><span class="subtitle-cursor"></span></div>

            <div class="form">
                <form class="js-removeTimeout" action="/login" method="POST">
                    <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>

                        <? if ($error) echo "<div class='error'>$error</div>"; ?>

                        <div class="field-label">Username</div>
                        <div class="input-row">
                            <span class="input-prompt">&#62;_</span>
                            <input name="username" type="text" placeholder="<?=_('Username')?>" autocapitalize="none" autocomplete="off" spellcheck="false" autofocus required>
                        </div>

                        <div class="field-label">Password</div>
                        <div class="input-row">
                            <span class="input-prompt">&#62;_</span>
                            <input name="password" type="password" placeholder="<?=_('Password')?>" required>
                        </div>

                        <? if ($twoFactorRequired && !empty($token)) { ?>
                            <input name="token" type="hidden" value="<?= $token ?>">
                        <? } ?>

                        <div class="btn-wrap">
                            <button type="submit" class="button button--small"><?=_('Login')?></button>
                        </div>

                    <? } else { ?>

                        <? if ($error) { ?>
                            <div class="error"><?= $error ?></div>
                        <? } else { ?>
                            <div class="error" title="<?= _('Please access this server via the My Servers Dashboard') ?>"><?= _('No 2FA token detected') ?></div>
                        <? } ?>
                        <a href="https://forums.unraid.net/my-servers/" class="button button--small" title="<?=_('Go to My Servers Dashboard')?>"><?=_('Go to My Servers Dashboard')?></a>

                    <? } ?>

                    <script type="text/javascript">
                        document.cookie = "cookietest=1";
                        cookieEnabled = document.cookie.indexOf("cookietest=") != -1;
                        document.cookie = "cookietest=1; expires=Thu, 01-Jan-1970 00:00:01 GMT";
                        if (!cookieEnabled) {
                            const e = document.createElement('div');
                            e.className = 'error';
                            e.textContent = "<?=_('Please enable cookies to use the Unraid webGUI')?>";
                            document.body.textContent = '';
                            document.body.appendChild(e);
                        }
                    </script>
                </form>

                <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>
                    <div class="js-addTimeout hidden">
                        <div class="error" style="margin-top:0.75rem;"><?=_('Transparent 2FA Token timed out')?></div>
                        <a href="https://forums.unraid.net/my-servers/" class="button button--small" title="<?=_('Go to My Servers Dashboard')?>"><?=_('Go to My Servers Dashboard')?></a>
                    </div>
                <? } ?>

                <!-- Status bar -->
                <div class="status-bar">
                    <div class="status-led"></div>
                    <span>Encrypted connection established</span>
                </div>
            </div>

            <? if (($twoFactorRequired && !empty($token)) || !$twoFactorRequired) { ?>
                <a href="https://docs.unraid.net/go/lost-root-password/" target="_blank" class="recovery js-removeTimeout"><?=_('Password recovery')?></a>
            <? } ?>
        </div>

    </section>

    <? if ($twoFactorRequired && !empty($token)) { ?>
        <script type="text/javascript">
            const $elsToRemove = document.querySelectorAll('.js-removeTimeout');
            const $elsToShow   = document.querySelectorAll('.js-addTimeout');
            const tokenName = '<?=$token?>'.slice(-20);
            const ts = Date.now();
            const timeoutStarted = sessionStorage.getItem(tokenName) ? Number(sessionStorage.getItem(tokenName)) : ts;
            const timeoutDiff = ts - timeoutStarted;
            const timeoutMS = 297000 - timeoutDiff;
            sessionStorage.setItem(tokenName, timeoutStarted);
            setTimeout(() => {
                $elsToRemove.forEach(z => z.remove());
                $elsToShow.forEach(z => z.classList.remove('hidden'));
            }, timeoutMS);
        </script>
    <? } ?>

    <script>
    (function () {
        // ── Matrix rain ──────────────────────────────────────────────────────
        const canvas = document.getElementById('matrix-canvas');
        const ctx    = canvas.getContext('2d');

        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
                      'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝﾞﾟ' +
                      '@#$%&:<>/\\|{}[]';

        const fontSize = 16;
        let columns, drops;

        function init() {
            canvas.width  = window.innerWidth;
            canvas.height = window.innerHeight;
            columns = Math.floor(canvas.width / fontSize);
            drops = Array.from({ length: columns }, () =>
                Math.floor(Math.random() * -(canvas.height / fontSize))
            );
        }

        function randChar() { return chars[Math.floor(Math.random() * chars.length)]; }

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.font = `${fontSize}px monospace`;

            for (let i = 0; i < drops.length; i++) {
                const x = i * fontSize;
                const head = drops[i];
                const headY = head * fontSize;

                // Bright white head character
                if (headY >= 0 && headY <= canvas.height) {
                    ctx.fillStyle = '#eefff0';
                    ctx.fillText(randChar(), x, headY);
                }

                // Two medium-green chars just behind the head
                for (let t = 1; t <= 2; t++) {
                    const ty = (head - t) * fontSize;
                    if (ty >= 0 && ty <= canvas.height) {
                        ctx.fillStyle = `rgba(0,255,65,${0.6 - t * 0.18})`;
                        ctx.fillText(randChar(), x, ty);
                    }
                }

                if (headY > canvas.height && Math.random() > 0.975)
                    drops[i] = Math.floor(Math.random() * -40);
                drops[i]++;
            }
            requestAnimationFrame(draw);
        }

        init();
        draw();
        window.addEventListener('resize', init);

        // ── Typewriter subtitle ───────────────────────────────────────────────
        const subtitleEl = document.getElementById('subtitle');
        const subtitleText = 'Access Terminal';
        let charIndex = 0;

        function typeWriter() {
            if (charIndex < subtitleText.length) {
                const cursor = subtitleEl.querySelector('.subtitle-cursor');
                subtitleEl.insertBefore(document.createTextNode(subtitleText[charIndex]), cursor);
                charIndex++;
                setTimeout(typeWriter, 75 + Math.random() * 40);
            }
        }

        setTimeout(typeWriter, 600);
    })();
    </script>
</body>
</html>
