# AI Analysis Trigger Activity Diagram

This diagram covers the AI analysis trigger flow across frontend and backend services.

```plantuml
@startuml
title AI Ticket Analysis Trigger - Activity Diagram

|User|
start
:Open ticket detail page;
:Click "Trigger AI analysis";

|Frontend|
:TicketDetailPage analyzeMutation;
:socApi.analyzeTicket -> POST /api/v1/tickets/{id}/analyze;

|Backend|
:TicketHandler.Analyze;
if (Ticket ID present?) then (yes)
  :Read JWT from context;
  if (JWT valid?) then (yes)
    :Decode optional request body;
    :TicketService.Analyze;
    :Build analyze API URL;
    if (Analyze API configured?) then (yes)
      :Load ticket detail;
      |DB|
      :Query tickets and related data;
      |Backend|
      if (Ticket exists?) then (yes)
        :Build analyze request payload;
        :POST to AI Analyze API (timeout);
        |AI Engine|
        :Process analysis request;
        |Backend|
        if (HTTP success and valid response?) then (yes)
          :Begin DB transaction;
          |DB|
          :Update ticket fields from analysis;
          :Upsert analysis;
          :Replace recommendations;
          :Replace MITRE techniques;
          :Insert audit log (ANALYZE_COMPLETED);
          |Backend|
          :Commit transaction;
          :Return AnalyzeTicketResponse;
          |Frontend|
          :Show success toast;
          :Invalidate ticket and tickets queries;
          stop
        else (no)
          :Validation error (analyze_api);
          |Frontend|
          :Show error toast;
          stop
        endif
      else (no)
        :404 Ticket not found;
        |Frontend|
        :Show error toast;
        stop
      endif
    else (no)
      :Validation error (analyze_api_url);
      |Frontend|
      :Show error toast;
      stop
    endif
  else (no)
    :401 Unauthorized;
    |Frontend|
    :Show error toast;
    stop
  endif
else (no)
  :400 Bad request;
  |Frontend|
  :Show error toast;
  stop
endif
@enduml
```

Sources:
- Backend: internal/handler/http/ticket.go, internal/service/ticket/service.go
- Frontend: src/pages/TicketDetailPage.tsx, src/api/soc.ts, src/lib/api.ts
