app.get('/master', (_req, res) => res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Master Admin — Steal An Egg</title>
  <style>
    *{box-sizing:border-box}
    body{
      margin:0;padding:30px 16px;min-height:100vh;
      background:#07111d;color:#e9f7ff;
      font:15px/1.5 system-ui,sans-serif
    }
    main{max-width:560px;margin:auto}
    .card{
      margin-top:20px;padding:22px;
      border:1px solid #25465d;border-radius:14px;
      background:#101f30
    }
    h1{font-size:27px}
    h2{font-size:19px}
    label{display:block;margin:12px 0 6px}
    input{
      width:100%;padding:12px;border-radius:7px;
      border:1px solid #31556c;background:#071522;
      color:#fff;font:inherit
    }
    button{
      margin-top:12px;padding:11px 16px;
      border:1px solid #59dbe9;border-radius:7px;
      background:#0b5368;color:#fff;
      font-weight:700;cursor:pointer
    }
    button:disabled{opacity:.5}
    .status{white-space:pre-wrap;overflow-wrap:anywhere}
    .error{color:#ff9696}
    .ok{color:#8bffb0}
    [hidden]{display:none!important}
  </style>
</head>
<body>
<main>
  <h1>Master Admin</h1>
  <p>Create and manage buyer access to the API.</p>

  <section class="card" id="loginCard">
    <h2>Master Login</h2>
    <form id="masterLoginForm">
      <label for="masterPassword">Master password</label>
      <input id="masterPassword" type="password"
        autocomplete="current-password" required>
      <button id="masterLoginButton" type="submit">
        Sign in
      </button>
    </form>
    <p id="loginStatus" class="status" aria-live="polite"></p>
  </section>

  <section class="card" id="workspace" hidden>
    <h2>Create Buyer Account</h2>
    <form id="addBuyerForm">
      <label for="newBuyerUsername">Buyer username</label>
      <input id="newBuyerUsername" maxlength="190"
        autocomplete="off" required>

      <label for="newBuyerPassword">Temporary password</label>
      <input id="newBuyerPassword" type="password"
        minlength="8" autocomplete="new-password" required>

      <button id="addBuyerButton" type="submit">
        Create Buyer
      </button>
    </form>

    <p id="addStatus" class="status" aria-live="polite"></p>
    <button id="masterLogout" type="button">Log out</button>
  </section>
</main>

<script>
(function(){
  'use strict';

  var token = '';
  var loginCard = document.getElementById('loginCard');
  var workspace = document.getElementById('workspace');
  var loginStatus = document.getElementById('loginStatus');
  var addStatus = document.getElementById('addStatus');

  function status(el, message, kind) {
    el.textContent = message || '';
    el.className = 'status' + (kind ? ' ' + kind : '');
  }

  function showWorkspace() {
    loginCard.hidden = true;
    workspace.hidden = false;
  }

  function resetLogin() {
    token = '';
    try { sessionStorage.removeItem('masterToken'); } catch(e) {}
    workspace.hidden = true;
    loginCard.hidden = false;
    document.getElementById('masterPassword').value = '';
  }

  async function request(path, method, payload, auth) {
    var headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    if (auth && token) {
      headers.Authorization = 'Bearer ' + token;
    }

    var response = await fetch(path, {
      method: method,
      headers: headers,
      body: payload === undefined
        ? undefined
        : JSON.stringify(payload),
      cache: 'no-store'
    });

    var data = await response.json().catch(function(){ return {}; });

    if (!response.ok || data.success === false) {
      throw new Error(
        data.error || ('Request failed (HTTP ' + response.status + ')')
      );
    }

    return data;
  }

  document.getElementById('masterLoginForm')
    .addEventListener('submit', async function(event) {
      event.preventDefault();

      var button = document.getElementById('masterLoginButton');
      button.disabled = true;
      status(loginStatus, 'Checking master credentials…');

      try {
        var data = await request(
          '/api/master/login',
          'POST',
          {
            password: document.getElementById('masterPassword').value
          },
          false
        );

        if (!data.token) {
          throw new Error('Master login did not return a session token.');
        }

        token = data.token;

        try {
          sessionStorage.setItem('masterToken', token);
        } catch(e) {}

        document.getElementById('masterPassword').value = '';
        status(addStatus, 'Signed in. You can create a buyer account.', 'ok');
        showWorkspace();
      } catch(error) {
        status(loginStatus, error.message || 'Master login failed.', 'error');
      } finally {
        button.disabled = false;
      }
    });

  document.getElementById('addBuyerForm')
    .addEventListener('submit', async function(event) {
      event.preventDefault();

      if (!token) {
        resetLogin();
        status(loginStatus, 'Please sign in again.', 'error');
        return;
      }

      var username =
        document.getElementById('newBuyerUsername').value.trim();
      var password =
        document.getElementById('newBuyerPassword').value;
      var button = document.getElementById('addBuyerButton');

      if (!username || password.length < 8) {
        status(addStatus,
          'Enter a username and a password of at least 8 characters.',
          'error');
        return;
      }

      button.disabled = true;
      status(addStatus, 'Creating buyer account…');

      try {
        var data = await request(
          '/api/master/add-user',
          'POST',
          { username: username, password: password },
          true
        );

        document.getElementById('newBuyerPassword').value = '';

        status(
          addStatus,
          'Buyer account created: ' + (data.username || username),
          'ok'
        );
      } catch(error) {
        if (/master authentication|required|invalid or expired token/i
            .test(error.message || '')) {
          resetLogin();
          status(loginStatus, 'Master session expired. Sign in again.', 'error');
        } else {
          status(addStatus, error.message || 'Could not create buyer.', 'error');
        }
      } finally {
        button.disabled = false;
      }
    });

  document.getElementById('masterLogout')
    .addEventListener('click', function() {
      resetLogin();
      status(loginStatus, 'Signed out.');
      status(addStatus, '');
    });

  try {
    token = sessionStorage.getItem('masterToken') || '';
  } catch(e) {
    token = '';
  }

  if (token) {
    showWorkspace();
  }
})();
</script>
</body>
</html>`));
