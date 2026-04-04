use crate::spec::ContainerSpec;

pub fn postgres(image: &'static str) -> ContainerSpec {
    // TODO: Setup a general postgres image with proper env, ports, etc.
    ContainerSpec::new(image)
}

pub fn image(image: &'static str) -> ContainerSpec {
    ContainerSpec::new(image)
}
