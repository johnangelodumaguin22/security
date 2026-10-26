<?php
require_once __DIR__ . '/header.php';
?>
<div class="page-container">
<?php
// ----- PAGE CONTENT GOES HERE -----
?>
</div>
<?php
require_once __DIR__ . '/footer.php';
?>
<?php
// Auto load CSS if exists
$css_path = __DIR__ . "/../CSS/{$title}.css";
$css_url = "../CSS/{$title}.css";

if (file_exists($css_path)) {
    echo "<link rel='stylesheet' href='{$css_url}'>";
}

// Auto load JS if exists
$js_path = __DIR__ . "/../HTML_PHP/js/{$page_js}";
$js_url = "../HTML_PHP/js/{$page_js}";

if (file_exists($js_path)) {
    echo "<script src='{$js_url}' defer></script>";
} else {
    // Redirect to 404 if JS missing
    header("Location: /SECURITY/page_not_found.php?missing={$page_js}");
    exit;
}
?>
