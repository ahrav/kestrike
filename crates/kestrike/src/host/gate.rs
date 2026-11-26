//! HOST-GATE: the private tuple field of [`HostGate`] confines direct construction to the `host::gate` module and
//! its descendants. Crate tests can call `HostGate::qualified`.

/// Code outside the crate names the type:
///
/// ```
/// fn admitted(_: &kestrike::host::HostGate) {}
/// ```
///
/// A literal, a constructor call and a default value outside the crate each fail to compile:
///
/// ```compile_fail,E0423
/// # use kestrike::host::HostGate;
/// let forged = HostGate(());
/// ```
///
/// ```compile_fail,E0599
/// # use kestrike::host::HostGate;
/// let qualified = HostGate::qualified();
/// ```
///
/// ```compile_fail,E0277
/// # use kestrike::host::HostGate;
/// let defaulted: HostGate = Default::default();
/// ```
pub struct HostGate(());

impl HostGate {
    /// Public visibility makes `#[cfg(test)]` the access boundary for the external `compile_fail` doctest on
    /// [`HostGate`]. Removing the attribute lets the constructor call compile, which fails the doctest.
    #[cfg(test)]
    pub fn qualified() -> Self {
        Self(())
    }
}

#[cfg(test)]
mod tests {
    use super::HostGate;

    #[test]
    fn a_test_build_qualifies_a_zero_sized_gate() {
        let gate = HostGate::qualified();
        assert_eq!(size_of_val(&gate), 0);
    }
}
