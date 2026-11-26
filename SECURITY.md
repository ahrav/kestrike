# Security policy

## Reporting a vulnerability

Report a suspected vulnerability through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. The report is visible only to the maintainer and to people
the maintainer adds.

Keep the details out of public issues, pull requests and discussions until a
fix is published.

Include what you can of the following:

- the commit you tested and the platform (architecture, kernel, device);
- the component (crate and module, script or workflow);
- what an attacker needs: local or network position, privileges, configuration;
- steps or a test that reproduce the problem, and what you observed;
- the effect: data exposure, corruption, privilege gain, or loss of service.

## What to expect

- An acknowledgement within 7 days.
- An assessment, with the planned fix or the reason no fix is planned, within
  30 days of the acknowledgement.
- Credit in the advisory when the fix is published, unless you ask to stay
  unnamed.

Disclosure is coordinated: the advisory and the fix are published together.
If 90 days pass from your report without a fix, you are free to publish.

## Supported versions

Kestrike has no releases. Fixes land on `main`, and `main` is the only
supported revision.

## Scope

In scope: the Rust crates, scripts, models and workflows in this repository.

Out of scope, with where to report instead:

- SPDK and DPDK, which `spdk-sys` links: report to those projects.
- Other dependencies: report to the dependency's maintainers. A report here
  is welcome when this repository's use of the dependency is what makes the
  problem reachable.
- AWS services and APIs: report to AWS Security.
- Findings that need physical access to the host, or root on a host that
  already runs the cache.
