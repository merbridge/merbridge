# Merbridge Governance

This is a document to govern Merbridge repos, documenting approximately how we have been operating up to this point.

## Principles

The Merbridge community adheres to the following principles:

* Open: Merbridge is open source. See [repository guidelines](#repository-guidelines) and [DCO](#dco), below.
* Welcoming and respectful: See [Code of Conduct](#code-of-conduct), below.
* Transparent and accessible: Work and collaboration should be done in public.
  See [team governance](#team-governance), below.
* Merit: Ideas and contributions are accepted according to their technical merit and
  alignment with project objectives, scope, and design principles.

## Code of Conduct

The Merbridge community abides by the [Merbridge code of conduct](./CODE_OF_CONDUCT.md).
Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of
fostering an open and welcoming community, we pledge to respect all people
who contribute through reporting issues, posting feature requests,
updating documentation, submitting pull requests or patches, and other activities._

As a member of the Merbridge project, you represent the project and your fellow contributors.
We value our community tremendously and we'd like to keep cultivating a friendly and
collaborative environment for our contributors and users. We want everyone in the community
to have positive experiences.

## Team governance

The Merbridge project is organized primarily into teams.
Each team is comprised of members from multiple
companies and organizations, with a common purpose of advancing the
project with respect to a specific topic, such as coding or documentation.
Our goal is to enable a distributed decision structure
and code ownership, as well as providing focused forums for getting
work done, making decisions, and onboarding new contributors. Every
identifiable subpart of the project (e.g., github org, repository,
subdirectory, API, test, issue, PR) is intended to be owned by some
team.

Merbridge currently has several teams like:

- cni-maintainers
- control-plane-maintainers
- doc-maintainers
- ebpf-prog-maintainers
- infra-maintainers
- istio-related-maintainers

A primary reason that teams exist is as forums for collaboration.
Much work in a team should stay local within that team. However, teams
must communicate in the open, ensure other teams and community members
can find notes of meetings, discussions, designs, and decisions, and
periodically communicate a high-level summary of the team's work to the
community.

Refer to [Merbridge CODEOWNERS](./CODEOWNERS) and [maintainers list](./MAINTAINERS.md).

### Subprojects

Specific work efforts within teams are divided into **subprojects**.
Every part of the Merbridge code and documentation must be owned by
some subproject. Some teams may have a single subproject, but many teams
have multiple significant subprojects with distinct (though sometimes
overlapping) sets of contributors and owners.

Merbridge has a few subprojects:

- [merbridge](https://github.com/merbridge/merbridge): the primary repo
- [website](https://github.com/merbridge/website): a website to <https://merbridge.io>
- [process-watcher](https://github.com/merbridge/process-watcher):
  a Go language library for observing the life cycle of system processes
- [bpftool](https://github.com/merbridge/bpftool): a tool to compile in a docker environment

Example subprojects for a few teams:

- cni-maintainers: focus on cni development and exploration
- control-plane-maintainers: focus on control-plane matters
- doc-maintainers: maintain website and its docs

Subprojects for each team are documented in [CODEOWNERS](./CODEOWNERS).

## Repository guidelines

All new repositories under Merbridge github orgs should follow the
process outlined in the Merbridge repository guidelines.

To facilitate contributions and collaboration from the broader Merbridge community,
contributions to Merbridge project are open with some guidelines below:

- All code projects use the Apache License version 2.0
- Must adopt the DCO bot automation for pull requests
- Add more soon

## DCO

All contributors must sign [DCO](https://wiki.linuxfoundation.org/dco).
That is, you shall run `git commit -s` to sign off your commit before opening a PR.

## License

Copyright 2024 the Merbridge Authors. All rights reserved.

Licensed under the Apache License, Version 2.0.

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fmerbridge%2Fmerbridge.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fmerbridge%2Fmerbridge?ref=badge_large)
