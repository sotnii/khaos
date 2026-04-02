use crate::spec::ContainerSpec;

pub fn postgres(image: &'static str) -> ContainerSpec {
    ContainerSpec {
        image: image.into(),
    }
}