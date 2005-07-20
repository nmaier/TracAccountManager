<?cs include "header.cs"?>
<?cs include "macros.cs"?>

<div id="ctxtnav" class="nav"></div>

<div id="content" class="register">

 <h1>My Account</h1>

 <p>
 Manage your user account.
 </p>

 <?cs if account.error ?>
 <div class="system-message">
  <h2>Error</h2>
  <p><?cs var:account.error ?></p>
 </div>
 <?cs /if ?>

 <?cs if account.message ?>
 <p><?cs var:account.message ?></p>
 <?cs /if ?>

 <form method="post" action="">
  <div>
   <input type="hidden" name="action" value="change_password" />
   <label for="password">New Password:</label>
   <input type="password" id="password" name="password" class="textwidget"
          size="20" />
  </div>
  <div>
   <label for="password_confirm">Confirm Password:</label>
   <input type="password" id="password_confirm" name="password_confirm"
          class="textwidget" size="20" />
  </div>
  <input type="submit" value="Change password" />
 </form>

 <form method="post" action=""
       onsubmit="return confirm('Are you sure you want to delete your account?');">
  <input type="hidden" name="action" value="delete" />
  <input type="submit" value="Delete account" />
 </form>

</div>

<?cs include:"footer.cs"?>
