<?php 
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
session_start();
require_once('includes/connect.php');
// include('recaptchalib.php');
require_once('includes/smtp.php');
// require_once('if-loggedin.php');

require 'PHPMailer-master/src/Exception.php';
require 'PHPMailer-master/src/PHPMailer.php';
require 'PHPMailer-master/src/SMTP.php';
$url = "https://apslup.com/";
// $secret = "6LcgH_wUAAAAAEy99Pf6fT9gW224bANcakapF6T6";

// $response = file_get_contents($url."?secret=".$secret."&response=".$_POST['g-recaptcha-response']."&remoteip=".$_SERVER['REMOTE_ADDR']);
// $reCaptcha = new JReCaptcha($secret);

if(isset($_POST) & !empty($_POST)){
    // PHP Form Validations
    if(empty($_POST['username'])){ $errors[]="User Name field is Required"; }else{
        // Check Username is Unique with DB query
        $sql = "SELECT * FROM users WHERE username=?";
        $result = $db->prepare($sql);
        $result->execute(array($_POST['username']));
        $count = $result->rowCount();
        if($count == 1){
            $errors[] = "User Name already exists in database";
        }
    }
    if(empty($_POST['email'])){ $errors[]="E-mail field is Required"; }else{
        // Check Email is Unique with DB Query
        $sql = "SELECT * FROM users WHERE email=?";
        $result = $db->prepare($sql);
        $result->execute(array($_POST['email']));
        $count = $result->rowCount();
        if($count == 1){
            $errors[] = "E-Mail already exists in database";
        }


    }
    if(empty($_POST['mobile'])){ $errors[]="Mobile field is Required"; }
    if(empty($_POST['password'])){ $errors[]="Password field is Required"; }else{
        // check the repeat password
        if(empty($_POST['passwordr'])){ $errors[]="Repeat Password field is Required"; }else{
            // compare both passwords, if they match. Generate the Password Hash
            if($_POST['password'] == $_POST['passwordr']){
                // create password hash
                $pass_hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
            }else{
                // Display Error Message
                $errors[] = "Both Passwords Should Match";
            }
        }
    }

    // Validation to check if Terms and Conditions are accepted
    if(!isset($errors)){
        if(!isset($_POST['terms'])) {
            $errors[] = "Please Accept terms and conditions.";
        }
    }else{
        $errors[] = "All fields are required.";
    }

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
        $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $result = $db->prepare($sql);
        $values = array(':username'     => $_POST['username'],
                        ':email'        => $_POST['email'],
                        ':password'     => $pass_hash
                        );
        $res = $result->execute($values);
        if($res){
            $messages[] = "User Registered Successfully";
            // get the id from last insert query and insert a new record into user_info table with mobile number
            $userid = $db->lastInsertID();
            $uisql = "INSERT INTO user_info (uid, mobile) VALUES (:uid, :mobile)";
            $uiresult = $db->prepare($uisql);
            $values = array(':uid'          => $userid,
                            ':mobile'       => $_POST['mobile']
                            );
            $uires = $uiresult->execute($values) or die(print_r($result->errorInfo(), true));
            if($uires){
                $messages[] = "Added User Meta Information";
                //Insert Activity into DB Table - user_activity
                $actsql = "INSERT INTO user_activity (uid, activity) VALUES (:uid, :activity)";
                $actresult = $db->prepare($actsql);
                $values = array(':uid'          => $userid,
                                ':activity'     => 'User Registered'
                                );
                $actresult->execute($values);
                $messages[] = 'Adding User Registration Log Entry';

                //Generating and Inserting Activation Token in DB Table - User_active
                $active_token = md5($_POST['username']).time();
                $activesql = "INSERT INTO user_active (uid, active_token) VALUES (:uid, :active_token)";
                $activeresult = $db->prepare($activesql);
                $values = array(':uid'              => $userid,
                                ':active_token'     => $active_token
                                );
                $activeresult->execute($values);
                
                //Send email to Registered user with PHPMailer
                $mail = new PHPMailer(true);

                try {
                    //Server settings
                    $mail->isSMTP();                                            // Send using SMTP
                    $mail->Host       = $smtphost;                              // Set the SMTP server to send through
                    $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
                    $mail->Username   = $smtpuser;                              // SMTP username
                    $mail->Password   = $smtppass;                              // SMTP password
                    $mail->SMTPSecure = 'tls';                                  // Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` encouraged
                    $mail->Port       = 587;                                    // TCP port to connect to, use 465 for `PHPMailer::ENCRYPTION_SMTPS` above

                    //Recipients
                    $mail->setFrom('info@apslup.com', 'Nwokeohuru chijindu');
                    //Update recipient email with dynamic email
                    $mail->addAddress('chijindu.nwokeohuru@apslup.com', 'Chijindu Nwokeohuru');     // Add a recipient

                    // Content
                    $mail->isHTML(true);                                  // Set email format to HTML
                    $mail->Subject = 'Apslup | Verify Your Email';
                    $mail->Body    = "{$url}activate.php?key={$active_token}&id={$userid}</b>";
                    $mail->AltBody = 'This is the body in plain text for non-HTML mail clients';

                    $mail->send();
                    $messages[] = "Activation Email has been sent. Please follow the instructions in your mail to continue to login page!";
                } catch (Exception $e) {
                    echo "Message could not be sent. Mailer Error: $mail->ErrorInfo";
                }
            }
        }
    } 
}
// CSRF Protection
// 1. Create CSRF token
$token = md5(uniqid(rand(), TRUE));
$_SESSION['csrf_token'] = $token;
$_SESSION['csrf_token_time'] = time();

// 2. add CSRF token to form
// 3. check the CSRF token on form submission
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, shrink-to-fit=no">
    <title>Register | Apslup </title>
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

                        <h1 class="">Get started<br/></h1>
                        <p class="signup-link">Already have an account? <a href="login.php">Log in</a></p>

                        <?php
                        if(!empty($errors)){
                            echo "<div class='alert alert-danger'>";
                            foreach ($errors as $error) {
                                echo "<span class='glyphicon glyphicon-remove'></span>&nbsp;".$error."<br>";
                            }
                            echo "</div>";
                        }
                        ?>
                        <?php
                            if(!empty($messages)){
                                echo "<div class='alert alert-success'>";
                                foreach ($messages as $message) {
                                    echo "<span class='glyphicon glyphicon-ok'></span>&nbsp;".$message."<br>";
                                }
                                echo "</div>";
                            }
                        ?>

                        <form class="text-left" role="form" method="post">
                            <input type="hidden" name="csrf_token" value="<?php echo $token; ?>">
                                <fieldset>
                                    <div class="form">

                                        <div id="username-field" class="field-wrapper input">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-user"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                                            <input class="form-control" placeholder="User Name" name="username" id="username" type="text" autofocus value="<?php if(isset($_POST['username'])){ echo $_POST['username']; } ?>"> <!-- retain the value inside the field -->
                                            <span id="usernameresults"></span> 
                                        </div>
                                        <div id="email-field" class="field-wrapper input">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-at-sign"><circle cx="12" cy="12" r="4"></circle><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"></path></svg>
                                            <input class="form-control" placeholder="E-mail" name="email" id="email" type="email" value="<?php if(isset($_POST['email'])){ echo $_POST['email']; } ?>"> <!-- retain the value inside the field -->
                                            <span id="emailresults"></span>
                                        </div>
                                        <div id="number-field" class="field-wrapper input">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-phone"><circle cx="12" cy="12" r="4"></circle><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg>
                                            <input class="form-control" placeholder="Mobile" name="mobile" type="number" value="<?php if(isset($_POST['mobile'])){ echo $_POST['mobile']; } ?>"> <!-- retain the value inside the field -->
                                        </div>
                                        <div id="password-field" class="field-wrapper input mb-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                                            <input class="form-control" placeholder="Password" name="password" type="password" value="">
                                        </div>
                                        <div id="password-field" class="field-wrapper input mb-2">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-key"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
                                            <input class="form-control" placeholder="Repeat Password" name="passwordr" type="password" value="">
                                        </div>
                                        <div class="field-wrapper terms_condition">
                                            <div class="n-chk new-checkbox checkbox-outline-primary">
                                                <label class="new-control new-checkbox checkbox-outline-primary">
                                                <input type="checkbox" class="new-control-input" name="terms">
                                                <span class="new-control-indicator"></span><span>I agree to the <a href="javascript:void(0);">  terms and conditions </a></span>
                                                </label>
                                            </div>
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
                                            <!-- <div class="g-recaptcha" data-sitekey="6LcgH_wUAAAAAOtT1Crh1wLshVqHWmjyBTwd6cbj">
                                            </div> -->
                                                <button type="submit" class="btn btn-warning" value="">Register</button>
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

    <!-- <script src="https://www.google.com/recaptcha/api.js?render=6LdLk7EUAAAAAEWHuB2tabMmlxQ2-RRTLPHEGe9Y"></script> -->
    <script type="text/javascript">
        var usernameresults = document.getElementById("usernameresults");
        var username = document.getElementById("username");

        function getUserNameResults(){
            var usernameVal = username.value;

            if(usernameVal.length < 1){
                usernameresults.style.display='none';
                return;
            }

            console.log('usernameVal : ' + usernameVal);
            var xhr = new XMLHttpRequest();
            var url = 'searchusername.php?search=' + usernameVal;

            //open function
            xhr.open('GET', url, true);

            xhr.onreadystatechange = function(){
                if(xhr.readyState == 4 && xhr.status == 200){
                    var text = xhr.responseText;
                    //console.log('response from searchresults.php : ' + xhr.responseText);
                    usernameresults.innerHTML = text;
                    usernameresults.style.display = 'block';
                }
            }
            xhr.send();
        }

        username.addEventListener("input", getUserNameResults);
    </script>
     <script type="text/javascript">
        var emailresults = document.getElementById("emailresults");
        var email = document.getElementById("email");

        function getEmailResults(){
            var emailVal = email.value;

            if(emailVal.length < 1){
                emailresults.style.display='none';
                return;
            }

            console.log('emailVal : ' + emailVal);
            var xhr = new XMLHttpRequest();
            var url = 'searchemail.php?search=' + emailVal;

            //open function
            xhr.open('GET', url, true);

            xhr.onreadystatechange = function(){
                if(xhr.readyState == 4 && xhr.status == 200){
                    var text = xhr.responseText;
                    //console.log('response from searchresults.php : ' + xhr.responseText);
                    emailresults.innerHTML = text;
                    emailresults.style.display = 'block';
                }
            }
            xhr.send();
        }

        email.addEventListener("input", getEmailResults);
    </script>
    <!-- BEGIN GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/libs/jquery-3.1.1.min.js"></script>
    <script src="bootstrap/js/popper.min.js"></script>
    <script src="bootstrap/js/bootstrap.min.js"></script>
    
    <!-- END GLOBAL MANDATORY SCRIPTS -->
    <script src="assets/js/authentication/form-1.js"></script>

</body>
</html>