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

---

## Standardized Test Suite

The test suite in `tests/test_api_endpoints.py` implements a standardized integration testing workflow using FastAPI's `TestClient` and an isolated, in-memory SQLite database.

### Core Testing Pillars

1. **Authentication Bypass**: The test suite mocks `app.main.validate_session` to bypass the `AuthMiddleware` cleanly, allowing endpoint verification without a live session state.
2. **Isolated Database State**: Tests override the `get_db` dependency using FastAPI's `dependency_overrides` mechanism. It binds to an in-memory SQLite database with `StaticPool` to preserve connection state and schema context between requests.
3. **Seeded Settings**: The test suite pre-populates database tables with default values before running tests.

### Running Endpoint Tests

To run the endpoint tests specifically:
```powershell
python -m unittest tests/test_api_endpoints.py -v
```

To run all unit tests (including endpoint tests):
```powershell
powershell -ExecutionPolicy Bypass -File .\validate.ps1
```
