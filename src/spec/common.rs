use crate::spec::ContainerSpec;

pub fn postgres(image: &'static str) -> ContainerSpec {
    // TODO: Setup a general postgres image with proper env, ports, etc.
    ContainerSpec {
        image: image.into(),
    }
}

pub fn image(image: &'static str) -> ContainerSpec {
    ContainerSpec {
        image: image.into(),
    }
}
