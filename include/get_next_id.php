<?php
// Preview only — the authoritative id_number is generated (and locked)
// server-side in register.php at insert time, ignoring whatever is posted.
// Kept in sync with the real generateNextId() in registration_helpers.php
// (format: INR-YYYY-NNNN, sequence resets each year) but deliberately not
// FOR UPDATE-locking here — this is a read-only preview, not a real claim
// on the next id.
include 'db_connect.php';

const ID_PREFIX = 'INR-';

function previewNextId($conn) {
    $year = $conn->query("SELECT YEAR(NOW()) y")->fetch_assoc()['y'];
    $likePattern = ID_PREFIX . $year . '-%';
    $stmt = $conn->prepare("SELECT id_number FROM users WHERE id_number LIKE ? ORDER BY id_number DESC LIMIT 1");
    $stmt->bind_param("s", $likePattern);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $last = $result->fetch_assoc()['id_number'];
        $seq = substr($last, strlen(ID_PREFIX) + strlen($year) + 1);
        $num = intval($seq) + 1;
    } else {
        $num = 1;
    }
    $padded = str_pad((string)$num, 4, "0", STR_PAD_LEFT);
    echo ID_PREFIX . $year . "-" . $padded;
}
previewNextId($conn);
?>
