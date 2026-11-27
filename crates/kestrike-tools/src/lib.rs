pub mod args;
pub mod fixtures;
pub mod git;
pub mod json;
pub mod ownership;
pub mod paths;
pub mod python;
pub mod rust_text;
pub mod shell;
pub mod text;
pub mod tools;

#[cfg(test)]
mod args_tests;
#[cfg(test)]
mod fixtures_tests;
#[cfg(test)]
mod git_tests;
#[cfg(test)]
mod json_tests;
#[cfg(test)]
mod paths_tests;
#[cfg(test)]
mod python_tests;
#[cfg(test)]
mod rust_text_tests;
#[cfg(test)]
mod shell_tests;
#[cfg(test)]
mod text_tests;
#[cfg(test)]
mod tools_tests;
