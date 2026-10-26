<?php
$missing = htmlspecialchars($_GET['missing'] ?? 'Unknown File');
?>
<!DOCTYPE html>
<html>
<head>
    <title>404 - File Not Found</title>
    <style>
        body {
            background: #0a0a0a;
            color: #eee;
            font-family: Arial;
            text-align: center;
            padding-top: 100px;
        }
        .box {
            background: #1a1a1a;
            padding: 30px;
            width: 350px;
            margin: auto;
            border-radius: 10px;
            box-shadow: 0 0 15px #000;
        }
        a { color: #5cb85c; text-decoration: none; }
    </style>
</head>
<body>
    <div class="box">
        <h1>404</h1>
        <p>File Not Found:</p>
        <b><?= $missing ?></b>
        <br><br>
        <a href="login.php">⬅ Back to Login</a>
    </div>
</body>
</html>
