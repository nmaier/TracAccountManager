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
  <fieldset>
   <legend>Required</legend>
   <div>
    <input type="hidden" name="action" value="create" />
    <label>Username:
     <input type="text" name="user" class="textwidget" size="20" />
    </label>
   </div>
   <div>
    <label>Password:
     <input type="password" name="password" class="textwidget" size="20" />
    </label>
   </div>
   <div>
    <label>Confirm Password:
     <input type="password" name="password_confirm"
            class="textwidget" size="20" />
    </label>
   </div>
  </fieldset>
  <fieldset>
   <legend>Optional</legend>
   <div>
    <label>Name:
     <input type="text" name="name" class="textwidget" size="20" />
    </label>
   </div>
   <div>
    <label>Email:
     <input type="text" name="email" class="textwidget" size="20" />
    </label>
    <?cs if reset_password_enabled ?>
    <p>Entering your email address will enable you to reset your
    password if you ever forget it.</p>
    <?cs /if ?>
   </div>
  </fieldset>
  <input type="submit" value="Create account" />
 </form>

</div>

<?cs include:"footer.cs"?>
