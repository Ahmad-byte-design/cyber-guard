Act as a senior Go backend engineer and API documentation architect.

PROJECT: CyberGuard AI
TASK: Implement complete, accurate Swagger/OpenAPI documentation for the existing Go backend.

IMPORTANT:
This is a backend-only project.

Do not build a Chrome extension, React application, frontend dashboard,
or any unrelated UI.

Swagger UI is required only as an interface for viewing and testing
the existing backend API.

==================================================
1. INSPECT THE EXISTING PROJECT
==================================================

Before modifying anything, inspect:

- The existing openapi.yaml file.
- README.md and API documentation.
- server/internal/httpapi/
- Actual HTTP handlers and routes.
- Request and response models.
- Error handling and HTTP status codes.
- Health and readiness endpoints.
- Docker Compose configuration.
- Configuration and environment variables.
- Existing tests and CI configuration.

Use the actual source code as the authority for implemented behavior.

The documentation must describe what the backend actually does,
not what we plan to implement in the future.

Do not replace a working API contract without a demonstrated reason.

==================================================
2. COMPLETE THE OPENAPI SPECIFICATION
==================================================

Inspect and update the existing openapi.yaml.

Prefer maintaining one authoritative OpenAPI specification rather
than generating a second specification that can drift from the code.

Document every implemented public HTTP endpoint, including the following
where they exist in the actual implementation:

- POST /api/v1/check-url
- GET /api/v1/get-url/{scanId}
- GET /api/v1/get-all
- GET /health/live
- GET /health/ready

Verify the precise paths and methods before documenting them.

For each endpoint, document:

- Summary and description.
- HTTP method and path.
- Path parameters.
- Query parameters, if supported.
- Required request headers.
- Request body schema.
- Required and optional properties.
- Response schemas.
- Successful HTTP status codes.
- Error status codes.
- Content types.
- Request and response examples.

Do not invent endpoints, parameters, fields, or response properties.

==================================================
3. DOCUMENT ASYNCHRONOUS SCANNING CORRECTLY
==================================================

Document the actual scan workflow.

For POST /api/v1/check-url, describe:

- Request validation.
- URL acceptance.
- HTTP 202 for an accepted asynchronous scan, where implemented.
- HTTP 200 when an existing fresh assessment is returned.
- Deduplication behavior.
- The scan ID and status URL when returned.
- Validation and rate-limit errors.

Document the actual response models.

For GET /api/v1/get-url/{scanId}, describe the scan lifecycle
and the available fields for each response state.

Distinguish between:

- queued
- running
- completed
- failed
- any other states actually defined by the implementation

A completed scan may contain a verdict, while queued or failed scans
must not be documented as having a valid security verdict.

Use the actual scan-state values in the code.

Document the existing verdict vocabulary:

- malicious
- suspicious
- no_threat_detected
- inconclusive
- unknown

Do not suggest that an unknown, incomplete, or failed scan means
the URL is safe.

==================================================
4. ERROR DOCUMENTATION
==================================================

Document the existing API error format, using
application/problem+json where implemented.

Include schemas and examples for relevant errors, such as:

- Malformed request.
- Invalid URL.
- Unsupported URL scheme.
- Private or prohibited target.
- Rate limit exceeded.
- Scan not found.
- Service unavailable.
- Provider analysis failure.

Use the actual response body and HTTP status code from the implementation.

Do not expose internal stack traces, secrets, raw provider error bodies,
or sensitive URL information in examples.

If the implementation differs from the documented RFC 9457 format,
report the discrepancy and correct it when appropriate.

==================================================
5. INTEGRATE SWAGGER UI
==================================================

Make the existing OpenAPI documentation available through Swagger UI.

Requirements:

1. Serve Swagger UI directly from the existing Go backend.
2. Provide a predictable documentation URL, preferably /docs/.
3. Serve the raw OpenAPI specification at /openapi.yaml.
4. Configure Swagger UI to load the locally served specification.
5. Configure the Swagger UI server selection for the local API at
   http://127.0.0.1:8080, while allowing users to select another
   documented server when appropriate.
6. Ensure the Try it out functionality sends requests to the configured
   backend instead of an unrelated server.
7. Ensure the documentation works with the existing Docker Compose setup.

Prefer pinned, self-hosted Swagger UI assets instead of relying on
an external CDN at runtime.

If embedding or bundling assets would introduce unnecessary complexity,
inspect the available options and choose a maintainable approach.

Do not introduce an unnecessary frontend framework.

Do not expose API keys, encryption keys, or other credentials through
the OpenAPI document or Swagger UI configuration.

==================================================
6. DOCUMENTATION ACCESS AND CONFIGURATION
==================================================

Add a configuration option such as API_DOCS_ENABLED if the project
does not already have an appropriate configuration mechanism.

Requirements:

- Swagger UI must be convenient to use in local development.
- Documentation access must be configurable for deployments.
- Do not introduce authentication just for Swagger UI.
- Do not add unnecessary dependencies to the request-processing path.
- Do not disable security controls to make Try it out work.

If the application already distinguishes development and production,
follow its established configuration conventions.

Update .env.example with non-secret configuration only.

==================================================
7. SCHEMA QUALITY
==================================================

Define reusable OpenAPI schemas under components/schemas.

Avoid duplicating the same request or response schema across endpoints.

Use correct types, formats, and required-property definitions.

Use appropriate schema definitions for:

- Scan submission requests.
- Scan submission responses.
- Scan status responses.
- Completed assessments.
- Evidence items.
- Ruleset responses.
- Readiness and health responses.
- Problem details.

Only include models supported by the current implementation.

Distinguish nullable properties from optional properties correctly.

Do not invent confidence scores, risk percentages, verdict values,
or provider fields that are not supported by the actual API contract.

Add realistic examples that do not contain real URLs submitted to
external providers, API keys, or other sensitive information.

==================================================
8. VALIDATION AND AUTOMATED TESTS
==================================================

Add tests or validation steps for the OpenAPI document.

Verify that:

- The OpenAPI YAML parses correctly.
- The declared schemas are valid.
- All documented paths correspond to implemented routes.
- Request and response examples match the actual handlers.
- Swagger UI can retrieve the specification.
- The documentation endpoint returns the correct content type.
- API Docs configuration behaves as documented.
- Existing API routes continue to work.
- Existing security and privacy tests still pass.

Use a suitable OpenAPI validator compatible with the project's
existing development workflow.

Avoid introducing an unnecessary Node.js runtime dependency into
the Go backend just for documentation validation.

Update CI to validate the OpenAPI document if a CI workflow already
exists or can be added consistently with the repository.

Run the relevant checks:

- gofmt
- go mod tidy
- go test ./...
- go test -race ./...
- go vet ./...
- go build ./...

Run the Docker build and relevant integration tests when possible.

Report commands that could not be executed instead of claiming
they passed.

==================================================
9. UPDATE PROJECT DOCUMENTATION
==================================================

Update README.md with:

- The Swagger UI URL.
- The raw OpenAPI specification URL.
- How to enable or disable documentation.
- How to start the API through Docker Compose.
- How to test an endpoint using Swagger UI.
- How to use curl for the same endpoint.
- Any limitations of Try it out.

Ensure the documentation reflects the actual local port and routes.

==================================================
10. SCOPE RESTRICTIONS
==================================================

Do not:

- Build a Chrome extension.
- Create a React application or separate frontend.
- Add unrelated business features.
- Make live Hybrid Analysis API requests.
- Add authentication or user accounts.
- Introduce Laravel or Elasticsearch.
- Invent new API endpoints just to populate Swagger.
- Remove existing API security validations.
- Put secrets in the OpenAPI specification or documentation.

==================================================
11. FINAL REPORT
==================================================

When finished, report:

1. Files created and modified.
2. Whether the existing OpenAPI specification was updated.
3. The exact URL for Swagger UI.
4. The exact URL for the raw OpenAPI document.
5. Which endpoints are documented.
6. How to test POST /api/v1/check-url using Try it out.
7. How to poll for scan results.
8. Tests and validation commands actually executed.
9. Remaining documentation or implementation discrepancies.

Provide exact commands that I can copy and paste to run and verify
the documentation locally.

Do not report a successful test unless it actually passed.