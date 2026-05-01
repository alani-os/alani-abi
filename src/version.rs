//! `version` module boundary.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionDescriptor<'a> {
    pub name: &'a str,
    pub version: u32,
}

impl<'a> VersionDescriptor<'a> {
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
