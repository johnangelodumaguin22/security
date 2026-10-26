<?php
include __DIR__ . '/db_connect.php'; // adjust path relative to this file

header('Content-Type: application/json; charset=utf-8');

if (!isset($_POST['username'])) {
    echo json_encode(['exists' => false, 'message' => '❌ No username received.']);
    exit;
}

$username = trim($_POST['username']);
if ($username === '') {
    echo json_encode(['exists' => false, 'message' => '❌ Username is required.']);
    exit;
}

if (preg_match('/\s/', $username)) {
    echo json_encode(['exists' => false, 'message' => '❌ Username cannot contain spaces.']);
    exit;
}

$username = strtolower($username);

$stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE LOWER(username) = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->bind_result($count);
$stmt->fetch();
$stmt->close();

if ($count > 0) {
    echo json_encode(['exists' => true, 'message' => '❌ Username already taken.']);
} else {
    echo json_encode(['exists' => false, 'message' => '✅ Username is available.']);
}

$conn->close();
