# Wazuh Raw Log Ingestion Activity Diagram

This diagram covers raw log batch ingestion from Wazuh into the backend and the resulting client updates.

```plantuml
@startuml
title Wazuh Raw Log Ingestion - Activity Diagram

|Wazuh|
start
:Send batch raw logs;
:POST /api/v1/webhook/wazuh/raw-logs;

|Backend|
:API key middleware;
if (API key valid?) then (yes)
  :WebhookHandler.IngestWazuhRawLogs;
  :Decode JSON body;
  if (Valid batch?) then (yes)
    :WebhookService.IngestRawLogs;
    :Begin DB transaction;
    :Finalize expired windows (pre);

    while (For each raw log)
      :Parse raw_log envelope;
      if (Window exists?) then (yes)
        :Update window stats
(severity, counts, expires);
        :Queue aggregating_updated event;
      else (no)
        :Create ingest window;
        :Create notifications for all users;
        :Queue aggregating_created event;
      endif
      :Insert window log row;
    endwhile

    :Finalize expired windows (post);
    note right
      Finalize expired windows:
      - Create ticket from window
      - Move window logs to ticket
      - Replace IOCs
      - Delete window
      - Notify users
      - Queue aggregating_closed event
    end note

    :Count active windows;
    :Commit transaction;
    :Publish stream events;
    :201 RawLogIngestResponse;
    |Frontend|
    :Receive SSE updates
(aggregating_* events);
    :Update ticket lists;
    stop
  else (no)
    :400 Validation error;
    |Wazuh|
    :Handle error response;
    stop
  endif
else (no)
  :401 Unauthorized;
  |Wazuh|
  :Handle error response;
  stop
endif
@enduml
```

Sources:
- Backend: internal/handler/http/webhook.go, internal/service/webhook/service.go
- Repository: internal/repository/postgresql/webhook_wazuh.go
- Frontend: src/hooks/useTicketsStream.ts
