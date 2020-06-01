<?php
session_start();
require_once('includes/connect.php');
// echo "SESSION ID : " . session_id();
$failmax = 5;
require_once('if-loggedin.php');

if (isset($_POST) & !empty($_POST)) {
    // PHP Form Validations
    if (empty($_POST['email'])) {
        $errors[] = "User Name / E-Mail field is Required";
    }
    if (empty($_POST['password'])) {
        $errors[] = "Password field is Required";
    }

    // CSRF Token Validation
    if (isset($_POST['csrf_token'])) {
        if ($_POST['csrf_token'] === $_SESSION['csrf_token']) {
        } else {
            $errors[] = "Problem with CSRF Token Validation";
        }
    }

    // CSRF Token Time Validation
    $max_time = 60 * 60 * 24; // in seconds
    if (isset($_SESSION['csrf_token_time'])) {
        $token_time = $_SESSION['csrf_token_time'];
        if (($token_time + $max_time) >= time()) {
        } else {
            $errors[] = "CSRF Token Expired";
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_time']);
        }
    }

    if (empty($errors)) {
        // Check the Login Credentials
        $sql = "SELECT * FROM users WHERE ";
        if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            $sql .= "email=?";
        } else {
            $sql .= "username=?";
        }
        $result = $db->prepare($sql);
        $result->execute(array($_POST['email']));
        $count = $result->rowCount();
        $res = $result->fetch(PDO::FETCH_ASSOC);
        if ($count == 1) {

            //Checking number of failed login attempts
            $failsql = "SELECT * FROM login_fail WHERE uid=? AND loginfailed > NOW() - INTERVAL 5 MINUTE";
            $failresult = $db->prepare($failsql);
            $failresult->execute(array($res['id']));
            $failcount = $failresult->rowCount();
            if ($failcount < $failmax) {

                // Compare the password with password hash
                if (password_verify($_POST['password'], $res['password'])) {
                    $messages[] = 'Create session and redirect user to their dashboard';

                    //Insert Activity into DB Table - user_activity
                    $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
                    $actresult = $db->prepare($actsql);
                    $values = array(
                        ':uid'          => $res['id'],
                        ':activity'     => 'User LoggedIn'
                    );
                    $actresult->execute($values);

                    //update logout time in login_log table, if previous logout record is blank insert the logout time

                    //select the query to get the record with blank logout time for the current logged in user
                    $logsql = "SELECT * FROM login_log WHERE uid=? AND loggedout='0000-00-00 00:00:00' ORDER BY id DESC LIMIT 1";
                    $logresult = $db->prepare($logsql);
                    $logresult->execute(array($res['id']));
                    $logcount = $logresult->rowCount();
                    $logres = $logresult->fetch(PDO::FETCH_ASSOC);
                    if ($logcount == 1) {
                        //update the logout time
                        $logoutsql = "UPDATE login_log SET loggedout=NOW() WHERE id=:id";
                        $logoutresult = $db->prepare($logoutsql);
                        $values = array(':id'          => $logres['id']); 
                        $logoutresult->execute($values);
                    }

                    // regenerate session id
                    session_regenerate_id();
                    $_SESSION['login'] = true;
                    $_SESSION['id'] = $res['id'];
                    $_SESSION['last_login'] = time();

                    // redirect the user to members area/dashboard page
                    header("location: index.php");
                    $_SESSION['username'] = $sql;
                } else {
                    //insert failed Login attempt  to user_activity table
                    $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
                    $actresult = $db->prepare($actsql);
                    $values = array(
                        ':uid'          => $res['id'],
                        ':activity'     => 'User Logged Failed'
                    );
                    $actresult->execute($values);

                    // insert failed login timestamps in login_failed table
                    $logfailsql = "INSERT INTO login_fail (uid) VALUES (:uid)";
                    $logfailresult = $db->prepare($logfailsql);
                    $values = array(':uid'          =>  $res['id']);
                    $logfailresult->execute($values);

                    //calculate the number of remaining attempts
                    $remainingattempts = $failmax - $failcount;

                    $errors[] = 'Invalid User Name / E-Mail & Password Combination';
                    $errors[] = "You have {$remainingattempts} login attempts remaining, otherwise you will be blocked for 10 minutes";
                }
            } else {
                $errors[] = 'You are now blocked from logging in, retry in 10 minutes';
            }
        } else {
            $errors[] = "User Name / E-Mail does not exist";
        }
    }
}
// 1. Create CSRF token
$token = md5(uniqid(rand(), TRUE));
$_SESSION['csrf_token'] = $token;
$_SESSION['csrf_token_time'] = time();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, shrink-to-fit=no">
    <title>Login page | Apslup </title>
    <link rel="icon" type="image/x-icon" href="assets/img/favicon.ico" />
    <!-- BEGIN GLOBAL MANDATORY STYLES -->
    <link href="https://fonts.googleapis.com/css?family=Nunito:400,600,700" rel="stylesheet">
    <link href="bootstrap/css/bootstrap.min.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/plugins.css" rel="stylesheet" type="text/css" />
    <link href="assets/css/authentication/form-1.css" rel="stylesheet" type="text/css" />
    <!-- END GLOBAL MANDATORY STYLES -->
    <link rel="stylesheet" type="text/css" href="assets/css/forms/theme-checkbox-radio.css">
    <link rel="stylesheet" type="text/css" href="assets/css/forms/switches.css">
</head>

<body class="form">


    <div class="form-container">
        <div class="form-form">
            <div class="form-form-wrap">
                <div class="form-container">
                    <div class="form-content">

                        <h1 class="">Log In to <a href="index.php"><span class="brand-name">APSLUP</span></a></h1>
                        <p class="signup-link">New Here? <a href="register.php">Create an account</a></p>

                        <?php
                        // echo "SESSION ID : " . session_id();
                        // echo "<pre>";
                        // print_r($_SESSION);
                        // echo "</pre>";
                        if (!empty($messages)) {
                            echo "<div class='alert alert-success'>";
                            foreach ($messages as $messages) {
                                echo "<span class='glyphicon glyphicon-ok'></span>&nbsp;" . $messages . "<br>";
                            }
                            echo "</div>";
                        }
                        ?>
                        <?php
                        if (!empty($errors)) {
                            echo "<div class='alert alert-danger'>";
                            foreach ($errors as $error) {
                                echo "<span class='glyphicon glyphicon-remove'></span>&nbsp;" . $error . "<br>";
                            }
                            echo "</div>";
                        }
                        ?>

                        <form class="text-left" role="form" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                            <fieldset>
                                <div class="form">

                                    <div id="username-field" class="field-wrapper input">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-user">
                                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                                            <circle cx="12" cy="7" r="4"></circle>
                                        </svg>
                                        <input id="username" name="email" class="form-control" placeholder="E-mail" type="text" autofocus value="<?php if (isset($_POST['email'])) {
                                                                                                                                                        echo $_POST['email'];
                                                                                                                                                    } ?>">
                                    </div>

                                    <div id="password-field" class="field-wrapper input mb-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock">
                                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                                        </svg>
                                        <input id="password" name="password" type="password" class="form-control" placeholder="Password">
                                    </div>
                                    <div class="d-sm-flex justify-content-between">
                                        <div class="field-wrapper toggle-pass">
                                            <p class="d-inline-block">Show Password</p>
                                            <label class="switch s-primary">
                                                <input type="checkbox" id="toggle-password" class="d-none">
                                                <span class="slider round"></span>
                                            </label>
                                        </div>
                                        <div class="field-wrapper">
                                            <button type="submit" class="btn btn-warning" value="">Log In</button>
                                        </div>

                                    </div>

                                    <div class="field-wrapper text-center keep-logged-in">
                                        <div class="n-chk new-checkbox checkbox-outline-primary">
                                            <label class="new-control new-checkbox checkbox-outline-primary">
                                                <input type="checkbox" class="new-control-input">
                                                <span class="new-control-indicator"></span>Keep me logged in
                                            </label>
                                        </div>
                                    </div>

                                    <div class="field-wrapper">
                                        <a href="auth_pass_recovery.html" class="forgot-pass-link">Forgot Password?</a>
                                    </div>

                                </div>
                            </fieldset>
                        </form>
                        <p class="terms-conditions">© 2020 All Rights Reserved. <a href="index.php">APSLUP</a> is a product of <a href="mailto:chijindu.nwokeohuru@gmail.com" target="_top">chijindu nwokeohuru </a>, <a href="pages_privacy.html">Privacy</a>, and <a href="pages_privacy.html">Terms</a>.</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="form-image">
            <div class="l-image">
            </div>
        </div>
    </div>


    <!-- BEGIN GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/libs/jquery-3.1.1.min.js"></script>
    <script src="bootstrap/js/popper.min.js"></script>
    <script src="bootstrap/js/bootstrap.min.js"></script>

    <!-- END GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/authentication/form-1.js"></script>

</body>

</html>