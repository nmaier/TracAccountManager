<h2>Manage User Accounts</h2>

<form id="addaccount" class="addnew" method="post">
 <fieldset>
  <?cs if registration.error ?>
  <div class="system-message"><p><?cs var:registration.error ?></p></div>
  <?cs /if ?>

  <legend>Add Account:</legend>
  <div class="field">
   <label>Username: <input type="text" name="user" class="textwidget" /></label>
  </div>
  <div class="field">
   <label>Password: <input type="password" name="password" class="textwidget" /></label>
  </div>
  <div class="field">
   <label>Confirm password: <input type="password" name="password_confirm" class="textwidget" /></label>
  </div>
  <p class="help">Add a new user account.</p>
  <div class="buttons">
   <input type="submit" name="add" value=" Add ">
  </div>
 </fieldset>
</form>

<form method="post">
 <table class="listing" id="accountlist">
  <thead>
   <tr><th class="sel">&nbsp;</th><th>Account</th></tr>
  </thead><tbody><?cs
  each:account = accounts ?>
   <tr>
    <td><input type="checkbox" name="sel" value="<?cs var:account ?>" /></td>
    <td><?cs var:account ?></td>
   </tr><?cs
  /each ?></tbody>
 </table>
 <div class="buttons">
  <input type="submit" name="remove" value="Remove selected accounts" />
 </div>
</form>


