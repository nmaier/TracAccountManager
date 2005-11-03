<?cs include "header.cs"?>
<?cs include "macros.cs"?>

<div id="ctxtnav" class="nav"></div>

<div id="content" class="login">

 <h1>Login</h1>

 <?cs if login.error ?>
 <div class="system-message">
  <h2>Error</h2>
  <p><?cs var:login.error ?></p>
 </div>
 <?cs /if ?>

 <form method="post" action="">
  <input type="hidden" name="referer" value="<?cs var:referer ?>" />
  <div>
   <label for="user">Username:</label>
   <input type="text" id="user" name="user" class="textwidget" size="20" />
  </div>
  <div>
   <label for="password">Password:</label>
   <input type="password" id="password" name="password" class="textwidget" size="20" />
  </div>
  <input type="submit" value="Login" />
 </form>

</div>

<?cs include:"footer.cs"?>
