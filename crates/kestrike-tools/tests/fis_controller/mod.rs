//! The cases of the FIS controller's checks and bounds, each over decoded inputs that
//! [`crate::fis_support`] builds: the rejection table run through the checks in [`rejections`], the
//! reads the checks make without a check of their own in [`reads`], each bound in [`bounds`], the lane's
//! close over hardware manifests in [`close`], the campaign budget of the checked-in profiles in
//! [`budget`], and the module's source in [`source`].

#![cfg(target_os = "linux")]

mod bounds;
mod budget;
mod close;
mod reads;
mod rejections;
mod source;

use std::path::Path;

use kestrike_tools::fis_controller::{
    Error, check_attachments, check_episode, check_grace, check_manifest, check_operator,
    check_profiles, positive_seconds,
};
use kestrike_tools::hardware_lane;
use kestrike_tools::json::Text;

use crate::fis_support::Inputs;

/// The check that stops a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    Poll,
    Operator,
    Manifest,
    Episode,
    Profiles,
    Attachments,
    Grace,
}

/// What stops a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// A rejection, or a refusal of the poll, with its sentence.
    Rejected(Text),
    /// A poll that spells no number.
    NoNumber,
    /// A whole number of seconds past the largest float.
    Overflow,
}

/// The checks of a run in the controller's order, over the hardware manifest at `hardware`: the poll,
/// the contract, the profiles file and the episode name, then, for the chosen profiles, their phases
/// against their cases, their attachment modes and their cleanup against the kill grace. The first
/// check that stops the run, with what stops it.
pub(crate) fn checks(inputs: &Inputs, hardware: &Path) -> Result<(), (Check, Stop)> {
    positive_seconds(&inputs.poll).map_err(|error| {
        let stop = match error {
            hardware_lane::Error::Refused(sentence) => Stop::Rejected(sentence),
            hardware_lane::Error::NoNumber => Stop::NoNumber,
            hardware_lane::Error::System(error) => panic!("a text's read fails with {error}"),
        };
        (Check::Poll, stop)
    })?;
    let rejected = |check| {
        move |error: kestrike_tools::fis_controller::Rejected| {
            (check, Stop::Rejected(error.sentence().clone()))
        }
    };
    let failed = |check| {
        move |error: Error| match error {
            Error::Rejected(error) => (check, Stop::Rejected(error.sentence().clone())),
            Error::Overflow => (check, Stop::Overflow),
        }
    };
    let (manifest, names, aws) = (&inputs.profiles, &inputs.names, inputs.aws_seconds);
    let operator = check_operator(&inputs.operator).map_err(rejected(Check::Operator))?;
    check_manifest(manifest).map_err(rejected(Check::Manifest))?;
    check_episode(&inputs.episode, manifest).map_err(rejected(Check::Episode))?;
    check_profiles(manifest, names, &operator, aws).map_err(failed(Check::Profiles))?;
    check_attachments(manifest, names, &operator).map_err(rejected(Check::Attachments))?;
    check_grace(manifest, names, &operator, aws, inputs.grace, hardware)
        .map_err(failed(Check::Grace))
}
