<?cs include "header.cs"?>
<?cs include "macros.cs"?>

<div id="ctxtnav" class="nav"></div>

<div id="content" class="register">

 <h1>Reset Password</h1>

 <?cs if reset.logged_in ?>
 <div class="system-message">
  <h2>Already logged in</h2>
  <p>
   You're already logged in.  If you need to change your password please use
   the <a href="<?cs var:account_href ?>">My Account</a> page.
  </p>
 </div>
 <?cs elif reset.sent_to_email ?>
 <p>A new password has been emailed to you at <?cs var:reset.sent_to_email ?>.</p>
 <?cs else ?>
 <p>
 If you've forgot your password enter your username and email address below and you'll be emailed a new password.
 </p>

 <?cs if reset.error ?>
 <div class="system-message">
  <h2>Error</h2>
  <p><?cs var:reset.error ?></p>
 </div>
 <?cs /if ?>

 <?cs if reset.message ?>
 <p><?cs var:reset.message ?></p>
 <?cs /if ?>

 <form method="post" action="">
  <div>
   <label>
    Username:
    <input type="text" name="username" class="textwidget" size="20" />
   </label>
  </div>
  <div>
   <label>
    Email Address:
    <input type="text" name="email" class="textwidget" size="20" />
   </label>
  </div>
  <input type="submit" value="Reset password" />
 </form>
 <?cs /if ?>

</div>

<?cs include:"footer.cs"?>

