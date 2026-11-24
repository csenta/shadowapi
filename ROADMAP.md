# ShadowAPI Roadmap

## Phase 1: Core Engine & Ingestion (Current)
- [x] HAR and traffic ingestion parser
- [x] Dynamic path token normalization (UUID, ID, hashes)
- [x] JSON Schema inference engine for request & response payloads
- [x] OpenAPI 3.1 synthesis module

## Phase 2: Drift & Vulnerability Analysis
- [x] Ground-truth vs Observed spec diff engine
- [x] Shadow endpoint detection (OWASP API9:2023)
- [x] Zombie endpoint detection
- [x] Schema parameter mutation & drift analysis
- [x] Authentication requirement discrepancy detector

## Phase 3: Reporting & CI/CD Gate
- [x] CLI interface with `synthesize`, `diff`, and `scan`
- [x] Interactive HTML dashboard with risk radar
- [x] Machine-readable JSON reporting for DevSecOps pipelines
- [x] Automated test suite & Docker containerization
