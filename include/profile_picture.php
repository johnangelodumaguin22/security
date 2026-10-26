<?php
// Profile picture upload — shared by dashboard.php, admin_dashboard.php, and
// superadmin_dashboard.php's "My Profile" pages. Kept in its own file since
// it's a self-contained, single-purpose concern (validate -> store -> point
// the users.profile_picture column at it), not part of registration/account
// validation.

const PROFILE_PICTURE_MAX_BYTES = 2 * 1024 * 1024; // 2 MB
const PROFILE_PICTURE_DIR = __DIR__ . '/../uploads/profile_pictures/';

// image/png etc, mapped to the extension we actually write to disk — never
// trust the client's filename/extension, only what getimagesize() detects.
const PROFILE_PICTURE_ALLOWED_TYPES = [
    IMAGETYPE_JPEG => 'jpg',
    IMAGETYPE_PNG  => 'png',
    IMAGETYPE_WEBP => 'webp',
];

// Validates and stores an uploaded profile picture for $idNumber, deleting
// whatever picture that account previously had. Returns
// ['status' => true, 'path' => 'uploads/profile_pictures/xxx.jpg'] or
// ['status' => false, 'message' => '...'].
function handleProfilePictureUpload($file, $idNumber, $previousPath) {
    if (!isset($file) || !is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return ['status' => false, 'message' => 'Please choose an image to upload.'];
    }
    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['status' => false, 'message' => 'Upload failed. Please try again.'];
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return ['status' => false, 'message' => 'Upload failed. Please try again.'];
    }
    if ($file['size'] > PROFILE_PICTURE_MAX_BYTES) {
        return ['status' => false, 'message' => 'Image must be 2 MB or smaller.'];
    }

    // The real, sniffed image type — never the client-supplied filename
    // extension or Content-Type header, both of which are trivially spoofed.
    $imageInfo = @getimagesize($file['tmp_name']);
    if ($imageInfo === false || !isset(PROFILE_PICTURE_ALLOWED_TYPES[$imageInfo[2]])) {
        return ['status' => false, 'message' => 'Only JPG, PNG, or WEBP images are allowed.'];
    }
    $ext = PROFILE_PICTURE_ALLOWED_TYPES[$imageInfo[2]];

    if (!is_dir(PROFILE_PICTURE_DIR)) {
        mkdir(PROFILE_PICTURE_DIR, 0755, true);
    }

    $filename = $idNumber . '_' . time() . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
    $destination = PROFILE_PICTURE_DIR . $filename;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['status' => false, 'message' => 'A server error occurred while saving the image. Please try again.'];
    }

    deleteProfilePictureFile($previousPath);

    return ['status' => true, 'path' => 'uploads/profile_pictures/' . $filename];
}

// Removes the physical file for a stored profile_picture DB value, if any.
// Safe to call with null/empty — a no-op in that case.
function deleteProfilePictureFile($relativePath) {
    if (!$relativePath) return;
    $full = __DIR__ . '/../' . $relativePath;
    if (is_file($full)) {
        @unlink($full);
    }
}

// The users.profile_picture column stores a path relative to the SECURITY
// root (e.g. "uploads/profile_pictures/x.jpg"); every page that renders it
// lives one level down in HTML_PHP/, so it needs "../" prepended.
function profile_picture_url($relativePath) {
    return $relativePath ? '../' . $relativePath : null;
}
