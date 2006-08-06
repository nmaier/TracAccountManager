<?cs include "header.cs"?>
<?cs include "macros.cs"?>

<div id="ctxtnav" class="nav"></div>

<div id="content" class="register">

 <h1>Register an account</h1>

 <?cs if registration.error ?>
 <div class="system-message">
  <h2>Error</h2>
  <p><?cs var:registration.error ?></p>
 </div>
 <?cs /if ?>

 <form method="post" action="">
  <div>
   <input type="hidden" name="action" value="create" />
   <label for="user">Username:</label>
   <input type="text" id="user" name="user" class="textwidget" size="20" />
  </div>
  <div>
   <label for="password">Password:</label>
   <input type="password" id="password" name="password" class="textwidget" size="20" />
  </div>
  <div>
   <label for="password_confirm">Confirm Password:</label>
   <input type="password" id="password_confirm" name="password_confirm"
          class="textwidget" size="20" />
  </div>
  <input type="submit" value="Create account" />
 </form>

</div>

<?cs include:"footer.cs"?>
