# DNS-AID Governance

This project governs the DNS-AID reference implementation and supports an ecosystem with planned hosting in the Linux Foundation. The DNS-AID specification itself is defined in the IETF.

## Scope

This project governs the reference implementation and ecosystem activities, including tooling, examples, integrations, documentation, and operational guidance.

The DNS-AID protocol specification is defined in the IETF. Protocol-level changes are out of scope for this project's governance.

## Roles

### Contributors

Anyone who submits a pull request, files an issue, or participates in discussions. Contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign off commits per the [Developer Certificate of Origin](https://developercertificate.org/).

### Committers

Contributors who have earned the ability to merge pull requests. Committers are responsible for code review, maintaining quality standards, and mentoring contributors.

**Current Committers:**

| Name | GitHub | Role |
|------|--------|------|
| Igor Racic | [@iracic82](https://github.com/iracic82) | Project Lead |

### Project Lead

The Project Lead provides overall technical direction. The Lead is elected by Committers and serves until they step down or are replaced by a vote.

## Decision Making

### Consensus

Most decisions are made through lazy consensus:

1. A proposal is submitted (issue, PR, or discussion)
2. If no Committer objects within 72 hours, the proposal is accepted
3. Silence is consent

### Voting

For significant decisions (architecture changes, new Committers, governance changes):

- Each Committer has one vote
- Decisions require a simple majority (>50%) of voting Committers
- Voting period is 7 days
- Votes are cast publicly in the relevant GitHub issue or discussion

### Conflict Resolution

1. Discuss in the relevant issue or PR
2. If no consensus after 7 days, Committers vote
3. If tied, the Project Lead has the casting vote

## Becoming a Committer

Any Contributor can be nominated for Committer status by an existing Committer. The nomination is voted on by existing Committers. Criteria include:

- Sustained contributions over at least 3 months
- Quality of code and reviews
- Understanding of the DNS-AID architecture and IETF draft
- Adherence to the Code of Conduct

## Maintainers

See [MAINTAINERS.md](MAINTAINERS.md) for the current list of maintainers and open roles. The project is actively seeking additional maintainers to ensure long-term sustainability and diverse representation across DNS providers, security expertise, and standards bodies.

## Modifying Governance

Changes to this governance document require a two-thirds majority vote of all Committers.

## Code of Conduct

All participants are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

All contributions are made under the [Apache License 2.0](LICENSE).
