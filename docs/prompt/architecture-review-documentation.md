Act as a Senior Software Architect, Go Backend Engineer, and
Cybersecurity Systems Architect with 10+ years of experience.

Your task is to review the architecture of CyberGuard AI,
identify design problems, make justified recommendations,
and produce complete technical documentation before implementation.

IMPORTANT:
This phase is for architecture design and documentation ONLY.

Do not implement application features.
Do not generate the entire application.
Do not create unnecessary source code.
Do not modify the implementation before the architecture is reviewed.

==================================================
1. PROJECT OVERVIEW
==================================================

Project Name: CyberGuard AI

CyberGuard AI is an open-source URL security platform that
integrates with a browser extension to identify potentially
malicious URLs and phishing websites.

The browser extension maintains a local cache and a versioned
set of browser protection rules.

When a URL is not available in the local cache, the extension
sends a request to the backend.

The backend checks whether a valid analysis result already exists.
If a fresh result is unavailable, it creates an asynchronous
analysis job and submits the URL to Hybrid Analysis API v2.

After the analysis is completed, the backend normalizes the result,
stores the necessary metadata, updates the relevant ruleset when
appropriate, and makes the result available to the extension.

The initial version will use Hybrid Analysis as its external
analysis provider. We are NOT building our own sandbox in this phase.

==================================================
2. TECHNOLOGY STACK
==================================================

Backend:
- Go
- net/http
- Chi router, if justified
- Official MongoDB Go Driver

Data Storage:
- MongoDB as the authoritative database
- Redis only if asynchronous job processing or caching requires it
- Elasticsearch is not part of the initial implementation

External Analysis:
- Hybrid Analysis API v2

Browser Extension:
- Chrome Extension Manifest V3
- declarativeNetRequest for supported browser protection rules
- chrome.storage.local for local extension data

Deployment:
- Docker
- Docker Compose

Testing:
- Go testing package
- httptest for HTTP API tests
- Integration tests for database and provider interactions

IMPORTANT:
Laravel has been removed entirely from the architecture.
Go is the primary backend language.

Do not introduce additional technologies without a concrete
technical reason.

==================================================
3. FIRST TASK: INSPECT THE EXISTING PROJECT
==================================================

Before proposing changes:

1. Inspect the repository structure.
2. Read CYBERGUARD_PROJECT.md completely if it exists.
3. Read CYBERGUARD_ARCHITECTURE_PROMPT.md if it exists.
4. Inspect existing documentation, Go modules, Docker files,
   configuration, and tests.
5. Identify contradictions, missing requirements, and outdated
   architectural decisions.
6. Do not assume that previously generated documents are correct.
7. Preserve valid existing work and avoid unnecessary rewrites.

If a required document is missing, continue using the project
description in this prompt and record the missing information
as an assumption.

Do not ask questions before producing the initial architecture proposal.
Make reasonable assumptions, document them explicitly, and identify
decisions that require confirmation before implementation.

==================================================
4. REVIEW THE SYSTEM ARCHITECTURE
==================================================

Evaluate the complete system architecture.

Determine the responsibilities and dependencies of:

- HTTP API
- URL Intelligence
- Scan Management
- Analysis Provider Integration
- Verdict Normalization
- Ruleset Management
- MongoDB Persistence
- Asynchronous Job Processing
- Configuration
- Observability
- Browser Extension Integration

Prefer a modular monolith for the initial Go backend.

Keep business logic independent of HTTP handlers, database-specific
implementation details, and external provider response formats.

Define clear module boundaries and dependency direction.

Explain which components are essential for the MVP and which should
be postponed.

Do not introduce microservices, Elasticsearch, or a custom sandbox
unless a specific requirement justifies them.

==================================================
5. DESIGN THE URL ANALYSIS LIFECYCLE
==================================================

Document the complete lifecycle:

1. The extension checks its local cache.
2. If an appropriate result is available, it follows the extension's
   configured handling policy.
3. Otherwise, the extension submits the URL to the Go API.
4. The backend validates and normalizes the URL.
5. The backend calculates a stable URL fingerprint.
6. MongoDB is checked for a valid existing assessment.
7. If a fresh assessment exists, return the stored verdict.
8. If an assessment is already running, reuse its job when appropriate.
9. Otherwise, create an asynchronous analysis job.
10. Submit the URL using the supported Hybrid Analysis API workflow.
11. Retrieve the analysis result.
12. Normalize the provider response into a CyberGuard verdict.
13. Save the result and metadata in MongoDB.
14. Update the browser ruleset if necessary.
15. Make the result available to the extension.
16. Expire or reassess results according to the documented policy.

Define explicit states, including:

- queued
- running
- completed
- failed
- expired

Distinguish the technical job status from the security verdict.

Possible normalized verdicts should include:

- malicious
- suspicious
- benign
- inconclusive
- unknown

Do not assume that every provider response maps directly to a
definitive safe or malicious classification.

Document retries, timeouts, duplicate-job prevention, provider
rate limits, and failure recovery.

==================================================
6. DESIGN THE API CONTRACTS
==================================================

Review and propose these API endpoints:

POST /api/v1/check-url

GET /api/v1/get-url/{scanId}

GET /api/v1/get-all?version={clientVersion}

You may recommend better REST conventions, but document the
reasons for any changes.

For every endpoint, specify:

- Purpose
- HTTP method and path
- Request schema
- Response schema
- Validation
- Status codes
- Error responses
- Rate limiting
- Security requirements

Define whether the initial request returns a cached result,
a queued analysis, or a currently running job.

Specify how the extension obtains the final analysis result.

Define ruleset versioning and explain when the server returns
the complete ruleset versus an unchanged-version response.

Do not claim that Chrome extensions can block every unknown
navigation while waiting for an arbitrary remote API response.
Document the limitations of Manifest V3 and declarativeNetRequest.

==================================================
7. REVIEW THE MONGODB DATA MODEL
==================================================

Design the collections, document fields, indexes, and expiration
strategy.

Consider separating:

- URL assessment records
- Analysis jobs
- Ruleset metadata
- Minimal provider references and analysis metadata

Do not retain raw URLs permanently by default.

Evaluate HMAC-SHA-256 fingerprints for exact-URL matching.
Keep fingerprint secrets exclusively on the backend.

Distinguish exact-URL reputation from hostname and registrable-domain
reputation.

Do not assume that different paths or subdomains have the same verdict.

Document:

- Unique indexes
- Lookup indexes
- Job deduplication
- TTL or explicit expiration
- Data retention
- Privacy-sensitive fields
- Whether provider responses are retained
- How raw URLs are handled temporarily

Do not use a plain unsalted hash as a claim of URL anonymization.

==================================================
8. REVIEW HYBRID ANALYSIS INTEGRATION
==================================================

Inspect the current official API documentation:

https://hybrid-analysis.com/docs/api/v2

Verify provider-specific endpoints, authentication requirements,
request schemas, status handling, and result retrieval.

Do not invent endpoint names, response fields, or capabilities.

Design a provider interface so that the rest of the application
does not depend on Hybrid Analysis-specific response formats.

Address:

- API key management
- Request and response mapping
- Polling or asynchronous completion
- Timeouts
- Rate limits
- Retries
- Provider unavailability
- Error normalization
- Result freshness
- Commercial-use restrictions and submission permissions

Never place the API key in the browser extension, source control,
logs, or client-visible responses.

Identify any API permissions that must be verified manually.

If a detail cannot be verified, mark it as an open question rather
than guessing.

==================================================
9. SECURITY AND PRIVACY REVIEW
==================================================

Evaluate the design for:

- SSRF risks
- Invalid URL schemes
- URL parsing inconsistencies
- DNS and redirect-related risks
- API abuse and excessive submissions
- Sensitive query parameters
- Raw URL logging
- API key exposure
- Queue duplication
- Stale security verdicts
- Malformed provider responses
- Unsafe ruleset generation
- False positives and false negatives
- Extension permission requirements
- Browser enforcement limitations

Do not automatically create permanent blocking rules from every
provider result.

Separate analysis findings from the policy that determines
whether an extension rule should be generated.

Explain how the system handles an inconclusive or failed analysis.

Do not classify failed analyses as benign.

==================================================
10. GO PROJECT STRUCTURE
==================================================

Propose a modular Go project structure.

Consider a structure similar to:

cmd/
  api/
  worker/

internal/
  config/
  transport/
    httpapi/
  modules/
    urlintel/
    scans/
    providers/
      hybridanalysis/
    verdicts/
    rulesets/
  platform/
    mongodb/
    queue/
    observability/
  app/

docs/
deploy/

Do not copy this structure blindly.

Explain the responsibilities of each package, its dependencies,
and which boundaries should be enforced by tests.

Keep the design idiomatic to Go.

Avoid unnecessary interfaces and excessive abstraction.

==================================================
11. DOCKER ARCHITECTURE
==================================================

Design the Docker Compose architecture for local development.

Consider:

- Go API
- Go worker
- MongoDB
- Redis, if required
- Configuration and environment variables
- Health checks
- Persistent development data
- Service-to-service networking

Separate essential services from optional services.

Do not expose databases or Redis publicly by default.

Never embed API secrets in Docker images.

Explain how the system will behave if MongoDB, Redis, or
Hybrid Analysis is unavailable.

==================================================
12. REQUIRED DOCUMENTATION
==================================================

Create or update the following documentation:

docs/architecture.md
docs/api-contract.md
docs/data-model.md
docs/module-map.md
docs/security-and-privacy.md
docs/hybrid-analysis-integration.md
docs/docker-development.md
docs/testing-strategy.md
docs/implementation-plan.md

Create architecture decision records under:

docs/decisions/

Use a clear naming convention such as:

0001-modular-monolith.md
0002-mongodb-as-source-of-truth.md
0003-asynchronous-analysis-jobs.md

Only create decision records for meaningful architectural choices.

Include Mermaid diagrams for:

- High-level architecture
- URL analysis sequence
- Module dependencies
- Scan state transitions
- Ruleset synchronization

Document assumptions, alternatives, trade-offs, and unresolved
decisions.

==================================================
13. TESTING STRATEGY
==================================================

Define a testing strategy that includes:

- URL normalization tests
- URL fingerprint tests
- API contract tests
- Scan lifecycle tests
- Job deduplication tests
- MongoDB integration tests
- Hybrid Analysis adapter tests
- Retry and timeout tests
- Verdict normalization tests
- Ruleset generation tests
- Security tests
- End-to-end tests

Use fake provider implementations for deterministic tests.

Do not perform uncontrolled submissions to external services
during automated testing.

Define acceptance criteria for the MVP.

==================================================
14. IMPLEMENTATION PLAN
==================================================

Create a phased implementation plan.

Phase 1:
Architecture and documentation.

Phase 2:
Go project foundation, configuration, logging, and health endpoints.

Phase 3:
MongoDB models, URL normalization, fingerprinting, and indexed lookup.

Phase 4:
Scan lifecycle, asynchronous jobs, and duplicate prevention.

Phase 5:
Hybrid Analysis provider integration.

Phase 6:
Verdict normalization and result retrieval.

Phase 7:
Versioned browser rulesets and extension API integration.

Phase 8:
Security hardening, tests, and Docker deployment.

For each phase, define:

- Scope
- Deliverables
- Dependencies
- Acceptance criteria
- Tests
- Risks

Keep the plan realistic for a small development team.

==================================================
15. FINAL EXECUTION RULES
==================================================

During this task:

- Inspect before editing.
- Write and update documentation only.
- Do not implement backend features.
- Do not modify application behavior.
- Do not install new dependencies.
- Do not generate large amounts of placeholder code.
- Do not introduce unnecessary technologies.
- Do not assume provider behavior that has not been verified.
- Document all assumptions and unresolved decisions.
- Keep the architecture practical, testable, and secure.

When finished, provide a summary containing:

1. The proposed architecture.
2. The module responsibilities.
3. The most important design decisions.
4. Any conflicts discovered in existing documentation.
5. The unresolved questions that require approval.
6. The recommended implementation order.
7. The exact documentation files created or updated.

STOP after completing the architecture review and documentation.

Wait for architectural approval before beginning implementation.