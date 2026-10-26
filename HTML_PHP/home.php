
<?php
session_start();
include '../include/db_connect.php';


// Optional: Redirect logged-in users to their dashboard
if (isset($_SESSION['user_type'])) {
  if ($_SESSION['user_type'] === 'admin') {
    header("Location: admin/dashboard.php");
    exit();
  } elseif ($_SESSION['user_type'] === 'student') {
    header("Location: student/dashboard.php");
    exit();
  }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Home | CSU Instructor Registration and Management</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
  <link rel="stylesheet" href="../CSS/home.css">

</head>
<body>
  <div class="overlay">
    <!-- NAVBAR -->
    <nav class="navbar navbar-expand-lg navbar-dark site-nav">
      <div class="container">
        <a class="navbar-brand site-nav__brand" href="home.php">
          <span class="site-nav__icon"><i class="bi bi-mortarboard-fill"></i></span>
          <span>CSU Instructor Registration and Management</span>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav ms-auto">
            <li class="nav-item"><a class="nav-link active" href="home.php"><i class="bi bi-house-door-fill"></i> Home</a></li>
            <li class="nav-item"><a class="nav-link" href="register.php"><i class="bi bi-person-plus-fill"></i> Register</a></li>
            <li class="nav-item"><a class="nav-link" href="login.php"><i class="bi bi-box-arrow-in-right"></i> Login</a></li>
          </ul>
        </div>
      </div>
    </nav>

    <!-- HERO SECTION -->
    <div class="container d-flex flex-column justify-content-center align-items-center flex-grow-1 py-4">
      <div class="hero-card text-center">
        <div class="hero-icon"><i class="bi bi-mortarboard-fill"></i></div>
        <p class="hero-eyebrow">CSU Instructor Registration and Management</p>
        <div class="hero-text">
          <h1 class="display-5 fw-bold">Welcome to CSU Instructor Registration and Management</h1>
          <p class="lead">Manage your personal and account information easily and securely.</p>
          <div class="mt-4">
            <a href="register.php" class="btn btn-custom me-3">Register Now</a>
            <a href="login.php" class="btn btn-secondary-custom">Login</a>
          </div>
        </div>
      </div>
    </div>

    <!-- FOOTER -->
      <footer class="text-center py-3">
      <p class="mb-0 text-white fw-medium">&copy; <?= date('Y') ?> CSU Instructor Registration and Management. All rights reserved.</p>
    </footer>

  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
  // Disable Right Click
  document.addEventListener("contextmenu", (e) => e.preventDefault());

  // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
  document.addEventListener("keydown", (e) => {
    if (
      e.key === "F12" ||
      (e.ctrlKey && e.shiftKey && (e.key === "I" || e.key === "J")) ||
      (e.ctrlKey && e.key === "U")
    ) {
      e.preventDefault();
    }
  });
  </script>
  <script>
  (function devtoolsDetector(){
    let element = new Image();
    Object.defineProperty(element, 'id', {
      get: function () {
        window.location.href = "about:blank";
      }
    });
    console.log(element);
  })();
  </script>

</body>
</html>
