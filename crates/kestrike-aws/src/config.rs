//! `Config::new` validates both labels it builds the endpoint host from,
//! so the host stays under `amazonaws.com`, and bounds the service
//! deadline by `MAX_DEADLINE`.

use std::time::Duration;

/// One AWS service's signing name and per-call limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// The SigV4 service name; `Config::new` uses it as the endpoint host
    /// prefix.
    pub name: &'static str,
    /// Each call's one deadline, measured from the start of
    /// `Client::send`. A paged EC2 read takes one such deadline at its
    /// start for all of its pages.
    pub deadline: Duration,
    /// The largest reply body a call accepts.
    pub body_cap: usize,
}

pub const DYNAMODB: Service = Service {
    name: "dynamodb",
    deadline: Duration::from_secs(1),
    body_cap: 1024 * 1024,
};

pub const EC2: Service = Service {
    name: "ec2",
    deadline: Duration::from_secs(10),
    body_cap: 4 * 1024 * 1024,
};

/// `MAX_DEADLINE` bounds `Service::deadline`. It keeps every sum of an
/// instant and `Service::deadline` that `Client` forms representable as an
/// `Instant`, and it is shorter than `REFRESH_MARGIN`. Each request runs
/// under a deadline at most `Service::deadline` after it starts, a page
/// under the read's shared deadline, so credentials found outside the
/// refresh margin at the credential check outlive the request's remaining
/// budget, measured by the clock that dated them. A constructor added beside `Config::new` applies the same bound.
pub const MAX_DEADLINE: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub(crate) service: Service,
    pub(crate) region: String,
    pub(crate) host: String,
}

impl Config {
    /// `Config::new` builds the endpoint host `<service>.<region>.amazonaws.com`
    /// and returns `None` unless `service.name` and `region` are each 1 to
    /// 32 bytes of lowercase ASCII letters, digits and hyphens,
    /// `service.deadline` is nonzero and at most `MAX_DEADLINE`, and
    /// `service.body_cap` is nonzero.
    pub fn new(service: Service, region: &str) -> Option<Self> {
        (is_label(service.name)
            && is_label(region)
            && !service.deadline.is_zero()
            && service.deadline <= MAX_DEADLINE
            && service.body_cap > 0)
            .then(|| Self {
                service,
                region: region.to_owned(),
                host: format!("{}.{region}.amazonaws.com", service.name),
            })
    }

    #[cfg(test)]
    pub(crate) fn at(mut self, host: String) -> Self {
        self.host = host;
        self
    }
}

fn is_label(text: &str) -> bool {
    (1..=32).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
