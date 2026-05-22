# Login Activity Diagram

This diagram covers the login flow across frontend and backend services.

```plantuml
@startuml
title Login Activity Diagram

|User|
start
:Enter username and password;
:Click "Sign in";

|Frontend|
:LoginPage onSubmit;
:AuthContext.login();
:socApi.login -> POST /api/v1/auth/login;

|Backend|
:AuthHandler.Login;
:Decode JSON body;
if (Valid request?) then (yes)
  :AuthService.Login;
  :Get user by username;
  |DB|
  :Query users;
  |Backend|
  if (User exists and password match?) then (yes)
    :Generate refresh token;
    :Create session;
    |DB|
    :Insert session;
    |Backend|
    :Generate access token;
    :200 TokenResponse;
    |Frontend|
    :Store tokens in localStorage;
    :socApi.me -> GET /api/v1/auth/me;
    |Backend|
    :AuthHandler.Me;
    if (JWT valid?) then (yes)
      :Get user by id;
      |DB|
      :Query users;
      |Backend|
      :200 User profile;
      |Frontend|
      :Set me state;
      :Navigate /tickets;
      stop
    else (no)
      :401 Unauthorized;
      |Frontend|
      :Show error message;
      stop
    endif
  else (no)
    :401 Invalid credentials;
    |Frontend|
    :Show error message;
    stop
  endif
else (no)
  :400 Validation error;
  |Frontend|
  :Show error message;
  stop
endif
@enduml
```

Sources:
- Backend: internal/handler/http/auth.go, internal/service/auth/service.go, internal/domain/auth/dto.go
- Frontend: src/pages/LoginPage.tsx, src/auth/AuthContext.tsx, src/api/soc.ts, src/lib/api.ts, src/lib/tokens.ts
