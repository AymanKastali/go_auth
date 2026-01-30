# Project AI Contract

## Architecture Paradigm
This project follows **Domain-Driven Design (Eric Evans) combined with Hexagonal Architecture (Ports & Adapters)**, strictly aligned with **Clean Architecture principles**.  

The architecture must:
- Enforce **domain purity**
- Follow **Eric Evans’ DDD rules strictly**
- Use **ports (interfaces) in the proper layer**
- Implement adapters in the **adapters layer** only (including infrastructure, delivery, and outer-world implementations)
- Prevent any dependency from domain or application layers to external frameworks or infrastructure
- Always apply **SOLID principles**, Clean Architecture patterns, and best practices
- Keep the codebase simple and maintainable

---

## Architecture Rules
- The project has **three layers only**:  
  1. **Domain** – Entities, Value Objects, Aggregates, Domain Services, Repositories (as interfaces / ports)  
  2. **Application** – Orchestrates use cases, coordinates domain objects, transaction boundaries, no domain logic leakage  
  3. **Adapters** – Implements all interfaces/ports from domain and application; includes infrastructure, delivery, and any external systems
- **Ports (interfaces)** must be defined in the layer that owns the behavior:  
  - Repository, service, and gateway interfaces belong in **domain** if they define business contracts  
  - Application-specific interfaces (if needed) belong in **application**
- Domain layer MUST NOT depend on application or adapters layers
- Application layer MUST NOT depend on adapters implementation
- Adapters layer may depend on domain and application layers
- Avoid unnecessary complexity; prefer clear, maintainable solutions
- Keep package-by-component (feature-first) organization

---

## Domain-Driven Design Rules (Eric Evans)
- Follow **Eric Evans tactical patterns strictly**
- Use **Entities, Value Objects, Aggregates, Repositories, Domain Services, Factories**
- Enforce **Aggregate boundaries and invariants**
- Only Aggregates have identity; Value Objects are immutable
- No anemic domain models—business logic must live in the domain model
- Ubiquitous Language must be reflected in code naming
- Avoid leaking infrastructure concerns into the domain or application layers
- Domain events should be raised inside aggregates when invariants change
- Apply best practices in DDD without overcomplicating the codebase

---

## Coding Standards
- Primary languages: Go and Python
- Prefer immutability and explicit Value Objects
- Explicit error handling (Go-style), no hidden exceptions
- Avoid global state and hidden side effects
- Apply **SOLID principles** strictly:
  - Single Responsibility, Open/Closed, Liskov, Interface Segregation, Dependency Inversion
- Keep code simple; avoid unnecessary abstractions or over-engineering
- Adhere to Clean Architecture boundaries and separation of concerns

---

## Domain Rules
- IDs must be Value Objects (not raw primitives)
- Domain Services contain **pure business logic only**
- Application layer coordinates use cases and transactions
- Adapters layer integrates databases, Redis, HTTP, message brokers, and external APIs
- No domain or application logic in adapters outside interface implementation

---

## AI Behavior Rules
- Do NOT violate architectural, DDD, or layer boundaries
- Ports (interfaces) must be created in the proper layer
- Do NOT import frameworks or infrastructure code into domain or application layers
- Prefer minimal, incremental refactors with explanations
- Ask for confirmation before large structural changes
- Generate tests when introducing or modifying business logic
- Always apply best practices
- Do NOT overcomplicate the codebase
- Prioritize clarity and maintainability over clever abstractions

---

## Project Context
This is a microservices backend system focused on authentication, device fingerprinting, and connect-matching features.
