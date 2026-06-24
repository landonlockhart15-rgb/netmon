# NetMon API Routes & Test Discovery Documentation

This document outlines the API endpoints exposed by the NetMon API backend and documents the standardized test suite created to protect against regression safety during network security updates.

## API Endpoint Reference

### Authentication
* **GET `/login`**: Serves the login page.
* **POST `/auth/login`**: Accepts username and password form fields, issues a session cookie, and redirects to the dashboard.
* **GET `/auth/logout`**: Revokes the active session cookie and redirects.

### System Status
* **GET `/api/status`**: Lightweight polling endpoint indicating running state of background loops (packet captures, AI analysis, network scans).

### Device Management
* **GET `/api/devices`**: Returns a list of devices seen in the current merge window.
* **PATCH `/api/device/{device_id}`**: Update device label, trusted status, or category.
* **POST `/api/device/{device_id}/allow`**: Configures port/protocol allowances for firewall automation checks.

### Monitoring & Settings
* **GET `/api/settings`**: Retrieves a flat key-value dictionary of all configuration parameters.
* **POST `/api/settings`**: Updates configuration parameters. Ignored if keys are locked by environment variables (e.g. `ntfy_pass`).

### AI Insights (introduced in commit 951e618 as `/api/ai/contextual-insight`)
* **POST `/api/ai/contextual-insight`**: Generates a 2-sentence summary explaining "What happened" and "Why it matters" for a given network security finding or health alert.

  #### Usage
  - **HTTP Method**: `POST`
  - **Endpoint**: `/api/ai/contextual-insight`
  - **Content-Type**: `application/json`
  - **Request Body**:
    - `text` (string, required): The main text of the alert or finding to analyze (1 to 5000 characters). Must not be empty or whitespace-only.
    - `context` (string, optional): Additional contextual information (e.g. system status, hostname, previous events) to assist the AI model (0 to 5000 characters).
  - **Response Body**:
    - `explanation` (string): The generated 2-sentence insight.
  - **Example Request**:
    ```json
    {
      "text": "Connection down",
      "context": "outage"
    }
    ```
  - **Example Response**:
    ```json
    {
      "explanation": "What happened: An offline event was detected. Why it matters: This means the local gateway is unreachable."
    }
    ```

  #### Security
  - **Authentication**: Access to this endpoint requires a valid user session. Unauthenticated requests return `401 Unauthorized` (managed by `AuthMiddleware`).
  - **Input Validation**:
    - The request body must be a valid JSON object.
    - `text` is required, must be a string, and cannot be empty or whitespace-only.
    - Strict boundary limit of 5000 characters is enforced on both `text` and `context` inputs to mitigate buffer overruns, parsing performance hits, and payload injection attacks.
  - **Error Sanitation**:
    - Exceptions thrown by the configured AI provider are caught and sanitized. Internal stack traces or credentials are never leaked to the client; instead, the endpoint returns a `500 Internal Server Error` with a safe, descriptive message.

  #### System Performance
  - **FastAPI Threading**: The route is implemented as a standard synchronous function (`def get_contextual_insight`). FastAPI executes synchronous endpoints on an external thread pool, preventing long-running AI provider I/O operations from blocking the main event loop.
  - **Activation Gate**: If AI features are disabled via the system setting `ai_enabled` (set to `"false"`), the endpoint returns a `400 Bad Request` immediately, avoiding any network overhead.
  - **Provider Dependency**: If the investigation provider is set to `"none"`, the endpoint returns a `400 Bad Request` immediately.
  - **Payload Size Limits**: The 5000-character payload limits keep memory footprint and external network request sizes minimal.

---

## Standardized Test Suite

The test suite in `tests/test_api_endpoints.py` implements a standardized integration testing workflow using FastAPI's `TestClient` and an isolated, in-memory SQLite database.

### Core Testing Pillars

1. **Authentication Bypass**: The test suite mocks `app.main.validate_session` to bypass the `AuthMiddleware` cleanly, allowing endpoint verification without a live session state.
2. **Isolated Database State**: Tests override the `get_db` dependency using FastAPI's `dependency_overrides` mechanism. It binds to an in-memory SQLite database with `StaticPool` to preserve connection state and schema context between requests.
3. **Seeded Settings**: The test suite pre-populates database tables with default values before running tests.
4. **Dynamic Route Security Discovery**: A dynamic security test (`test_route_security_discovery`) programmatically scans the live FastAPI route registry (`app.routes`) on every test run. It resolves path parameters and verifies that every endpoint correctly enforces authentication policies (returning `401` for `/api/*` routes, redirecting `303` to `/login` for UI and static files, or passing through for exempt paths).

### Coverage and Verification

The test suite covers:
* **Authentication Flow**: Validates session setup, teardown, and cookie assignment on `/auth/login` and `/auth/logout` endpoints, as well as access to the `/login` static file.
* **Device Management**: Verifies metadata patch updates (`PATCH /api/device/{device_id}`) and allow-listing options (`POST /api/device/{device_id}/allow`) to ensure firewall policies map correctly.
* **Telemetry & Settings**: Ensures status check, settings lookup/updates, and AI explanation functions perform as expected.

### Running Endpoint Tests

To run the endpoint tests specifically:
```powershell
python -m unittest tests/test_api_endpoints.py -v
```

To run all unit tests (including endpoint tests):
```powershell
powershell -ExecutionPolicy Bypass -File .\validate.ps1
```

