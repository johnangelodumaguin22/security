<?php
if (!isset($title)) $title = "Security System";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title); ?></title>

    <!-- GLOBAL CSS -->
    <link rel="stylesheet" href="/SECURITY/CSS/home.css">
    <link rel="stylesheet" href="/SECURITY/CSS/login.css">
    <link rel="stylesheet" href="/SECURITY/CSS/register.css">
    <link rel="stylesheet" href="/SECURITY/CSS/dashboard.css">

    <?php 
    if (!empty($page_css)) {
        echo '<link rel="stylesheet" href="/SECURITY/CSS/' . htmlspecialchars($page_css) . '">';
    }
    ?>
</head>
<body>
