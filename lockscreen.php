<?php 
session_start();
require_once('includes/connect.php');
require_once('if-loggedin.php');

if(isset($_POST) & !empty($_POST)){
    // PHP Form Validations
    if(empty($_POST['password'])){ $errors[]="Password field is Required"; }
    // CSRF Token Validation
    if(isset($_POST['csrf_token'])){
        if($_POST['csrf_token'] === $_SESSION['csrf_token']){
        }else{
            $errors[] = "Problem with CSRF Token Validation";
        }
    }
    // CSRF Token Time Validation
    $max_time = 60*60*24; // in seconds
    if(isset($_SESSION['csrf_token_time'])){
        $token_time = $_SESSION['csrf_token_time'];
        if(($token_time + $max_time) >= time() ){
        }else{
            $errors[] = "CSRF Token Expired";
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_time']);
        }
    }

    if(empty($errors)){
        // Check the Login Credentials
        $sql = "SELECT * FROM users WHERE ";
        if(filter_var($_POST['password'], FILTER_VALIDATE_EMAIL)){
            $sql .= "password=?";
        }else{
            $sql .= "username=?";
        }
        $result = $db->prepare($sql);
        $result->execute(array($_POST['password']));
        $count = $result->rowCount();
        $res = $result->fetch(PDO::FETCH_ASSOC);
        if($count == 1){
            // Compare the password with password hash
            if(password_verify($_POST['password'], $res['password'])){
                // regenerate session id
                session_regenerate_id();
                $_SESSION['login'] = true;
                $_SESSION['id'] = $res['id'];
                $_SESSION['last_login'] = time();

                // redirect the user to members area/dashboard page
                header("location: index.php");
                }else{
            $errors[] = "Password not Valid";
            }
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
    <title>Lockscreen | Apslup </title>
    <link rel="icon" type="image/x-icon" href="assets/img/favicon.ico"/>
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

                        <div class="d-flex user-meta">
                            <img src="assets/img/90x90.jpg" class="usr-profile" alt="avatar">
                            <div class="">
                                <p>
                                    
                                </p>
                            </div>
                        </div>

                        <?php
                            if(!empty($errors)){
                                echo "<div class='alert alert-danger'>";
                                foreach ($errors as $error) {
                                    echo "<span class='glyphicon glyphicon-remove'></span>&nbsp;".$error."<br>";
                                }
                                echo "</div>";
                            }
                        ?>

                        <form class="text-left" role="form" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                <fieldset>
                                    <div class="form">

                                        <div id="password-field" class="field-wrapper input mb-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
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
                                                <button type="submit" class="btn btn-warning" value="">Unlock</button>
                                            </div>
                                            
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