use crate::containers::manager::ContainerManagerError::{
    ConnectionUninitialized, UnexpectedImageTargetMediaType,
};
use crate::net::manager::NetworkNamespace;
use crate::spec::{ContainerSpec, NodeId};
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::services::v1::images_client::ImagesClient;
use containerd_client::services::v1::transfer_client::TransferClient;
use containerd_client::services::v1::{
    GetImageRequest, Image, ReadContentRequest, TransferOptions, TransferRequest,
};
use containerd_client::tonic::transport::{Channel, Error as TonicError};
use containerd_client::tonic::{Code, Request, Status};
use containerd_client::types::transfer::{ImageStore, OciRegistry, UnpackConfiguration};
use containerd_client::types::Platform;
use containerd_client::{to_any, with_namespace};
use oci_spec::image::{
    Config, Descriptor, ImageConfiguration, ImageIndex, ImageManifest, MediaType,
};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, ProcessBuilder, RootBuilder, Spec,
    SpecBuilder, UserBuilder,
};
use oci_spec::OciSpecError;
use serde_json::Error;
use std::env::consts;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, debug_span, info_span, instrument};

#[derive(Debug, Error)]
pub enum ContainerManagerError {
    #[error("connection to containerd is not initialized")]
    ConnectionUninitialized,
    #[error("failed to establish containerd connection")]
    ConnectionFailed(#[source] TonicError),
    #[error("failed to pull image")]
    ImagePullFailed(String, #[source] Status),
    #[error("failed to read content blob from containerd")]
    ContentReadFailed(#[source] Status),
    #[error("failed to parse contents of a containerd document")]
    ParsingFailed(#[source] Error),
    #[error("")]
    ImageConfigMissing,
    #[error("failed to build oci spec")]
    OciSpecBuildFailed(#[from] OciSpecError),
    #[error("image index is missing manifest suitable for current arch")]
    ImageManifestNotFoundForCurrentArch,
    #[error("unexpected image target media type: {0}, expected image index or image manifest")]
    UnexpectedImageTargetMediaType(MediaType),
}

pub struct ContainerManager {
    channel: Option<Channel>,
    container_logs_path: Option<PathBuf>,
}

const CONTAINERD_SOCK: &str = "/run/containerd/containerd.sock";
const CONTAINERD_NAMESPACE: &str = "khaos";
const SNAPSHOTTER: &str = "overlayfs";
const RUNTIME_NAME: &str = "io.containerd.runc.v2";
const OCI_RUNTIME_SPEC_VER: &str = "1.3.0";

const ROOTFS_PATH: &str = "rootfs";

impl ContainerManager {
    // TODO:
    //  +1. Pull image if missing
    //  2. Create & run container task
    //      * container id should be like: kh-<test_id>-<node_id>-(<image_basename>-<uuid>|<custom_name>)
    //      * put test, node, image in container metadata as well
    //      +2.1 +oci_spec that joins netns
    //  3. Collect logs into tmp directory by test id and container id
    //      * logs should be collected to /tmp/khaos/<test_name>-<test_id>/<container_id>/<stdout|stderr>
    //  4. Run the container task
    //  5. Upon teardown, collect logs, container fs (by flag), stop the task and remove snapshot
    //      * logs and container fs should be collected in ./artifacts/<test_name>-<test_id>/:
    //          - logs/<node_id>/(<image_basename>-<uuid>|<custom_name>)/output/<stdout|stderr> - container logs (copied from tmp dir)
    //          - fs/rootfs.tar - tar

    pub fn new(container_logs_path: Option<PathBuf>) -> ContainerManager {
        ContainerManager {
            channel: None,
            container_logs_path,
        }
    }

    #[instrument(name = "containerd.connect", skip(self), err)]
    pub async fn connect(&mut self) -> Result<(), ContainerManagerError> {
        let channel = containerd_client::connect(CONTAINERD_SOCK)
            .await
            .map_err(ContainerManagerError::ConnectionFailed)?;
        self.channel = Some(channel);
        Ok(())
    }

    fn ensure_connected(&self) -> Result<Channel, ContainerManagerError> {
        if self.channel.is_none() {
            return Err(ConnectionUninitialized);
        }
        Ok(self.channel.clone().unwrap())
    }

    pub async fn run_container(
        &mut self,
        test_id: String,
        node_id: NodeId,
        container_spec: ContainerSpec,
        ns: NetworkNamespace,
    ) -> Result<(), ContainerManagerError> {
        let image = self.pull_image(&container_spec.image_ref).await?;
        let cfg = self.get_image_config(&image).await?;
        let spec = self.build_oci_spec(&ns.path, cfg)?;

        debug!(spec = serde_json::to_string(&spec).unwrap(), "spec built");

        Ok(())
    }

    async fn pull_image(&self, image_ref: &String) -> Result<Image, ContainerManagerError> {
        let _span = info_span!(
            "pulling image",
            image = %image_ref,
        )
        .entered();
        let ch = self.ensure_connected()?;
        let img = self.fetch_image(image_ref).await?;
        if let Some(i) = img {
            return Ok(i);
        }

        let arch = normalize_arch(consts::ARCH);
        let platform = Platform {
            os: "linux".to_string(),
            architecture: arch.to_string(),
            variant: "".to_string(),
            os_version: "".to_string(),
        };

        let source = OciRegistry {
            reference: image_ref.to_string(),
            resolver: Default::default(),
        };

        let destination = ImageStore {
            name: image_ref.to_string(),
            platforms: vec![platform.clone()],
            unpacks: vec![UnpackConfiguration {
                platform: Some(platform),
                ..Default::default()
            }],
            ..Default::default()
        };

        let mut transfer = TransferClient::new(ch.clone());
        transfer
            .transfer(with_namespace!(
                TransferRequest {
                    source: Some(to_any(&source)),
                    destination: Some(to_any(&destination)),
                    options: Some(TransferOptions {
                        ..Default::default()
                    }),
                },
                CONTAINERD_NAMESPACE
            ))
            .await
            .map_err(|e| ContainerManagerError::ImagePullFailed(image_ref.clone(), e))?;

        let pulled_image = self.fetch_image(image_ref).await?;
        Ok(pulled_image
            .expect("expected to successfully fetch image from containerd after TransferRequest"))
    }

    #[instrument(skip(self), err)]
    async fn fetch_image(
        &self,
        image_ref: &String,
    ) -> Result<Option<Image>, ContainerManagerError> {
        let ch = self
            .channel
            .as_ref()
            .expect("containerd channel was not setup");
        let mut images = ImagesClient::new(ch.clone());

        let resp = images
            .get(with_namespace!(
                GetImageRequest {
                    name: image_ref.clone()
                },
                CONTAINERD_NAMESPACE
            ))
            .await;

        match resp {
            Err(e) if e.code() == Code::NotFound => Ok(None),
            Err(e) => Err(ContainerManagerError::ImagePullFailed(image_ref.clone(), e)),
            Ok(r) => {
                let r = r.get_ref().clone();
                Ok(Some(r.image.expect(
                    "image expected to be present in containerd GetImageRequest response",
                )))
            }
        }
    }

    async fn get_image_config(&self, image: &Image) -> Result<Config, ContainerManagerError> {
        let _span = debug_span!("get image config", image = image.name).entered();
        let manifest = self.resolve_image_manifest(&image).await?;

        let config_desc = manifest.config();
        let config_bytes = self
            .read_content_to_blob(&config_desc.digest().to_string())
            .await?;
        let image_config = ImageConfiguration::from_reader(config_bytes.as_slice())?;
        let cfg = image_config.config().as_ref();
        if cfg.is_none() {
            return Err(ContainerManagerError::ImageConfigMissing);
        }

        Ok(cfg.unwrap().clone())
    }

    #[instrument(skip(self), err)]
    async fn resolve_image_manifest(
        &self,
        image: &Image,
    ) -> Result<ImageManifest, ContainerManagerError> {
        let target = image
            .target
            .clone()
            .expect("image expected to have target descriptor");

        let target_bytes = self.read_content_to_blob(&target.digest).await?;
        match MediaType::from(target.media_type.as_str()) {
            MediaType::ImageManifest => Ok(ImageManifest::from_reader(target_bytes.as_slice())?),
            MediaType::ImageIndex => {
                let index = ImageIndex::from_reader(target_bytes.as_slice())?;
                let manifest_descriptor = self.resolve_manifest_from_index(&index)?;
                let manifest_blob = self
                    .read_content_to_blob(&manifest_descriptor.digest().to_string())
                    .await?;

                Ok(ImageManifest::from_reader(manifest_blob.as_slice())?)
            }
            typ => Err(UnexpectedImageTargetMediaType(typ)),
        }
    }

    fn resolve_manifest_from_index(
        &self,
        index: &ImageIndex,
    ) -> Result<Descriptor, ContainerManagerError> {
        let manifest = index.manifests().iter().find(|m| {
            if let Some(p) = m.platform() {
                p.os().to_string() == consts::OS
                    && p.architecture().to_string() == normalize_arch(consts::ARCH)
            } else {
                false
            }
        });
        if manifest.is_none() {
            return Err(ContainerManagerError::ImageManifestNotFoundForCurrentArch);
        }
        Ok(manifest.unwrap().clone())
    }

    async fn read_content_to_blob(&self, digest: &str) -> Result<Vec<u8>, ContainerManagerError> {
        let ch = self.ensure_connected()?;
        let mut content = ContentClient::new(ch);

        let mut stream = content
            .read(with_namespace!(
                ReadContentRequest {
                    digest: digest.to_string(),
                    offset: 0,
                    size: 0, // 0 = entire blob
                },
                CONTAINERD_NAMESPACE
            ))
            .await
            .map_err(ContainerManagerError::ContentReadFailed)?;

        let mut out = Vec::new();

        let stream = stream.get_mut();
        while let Some(chunk) = stream
            .message()
            .await
            .map_err(ContainerManagerError::ContentReadFailed)?
        {
            out.extend_from_slice(&chunk.data);
        }

        Ok(out)
    }

    // TODO: should support overrides from ClusterSpec
    fn build_oci_spec(&self, netns_path: &str, image_cfg: Config) -> Result<Spec, OciSpecError> {
        let entrypoint = image_cfg.entrypoint().clone().unwrap_or_default();
        let cmd = image_cfg.cmd().clone().unwrap_or_default();

        let mut args = Vec::new();
        args.extend(entrypoint.into_iter().filter(|s| !s.is_empty()));
        args.extend(cmd.into_iter().filter(|s| !s.is_empty()));

        let cwd = image_cfg
            .working_dir()
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/".to_string());

        let env = image_cfg.env().clone().unwrap_or_default();

        let process = ProcessBuilder::default()
            .args(args)
            .cwd(cwd)
            .env(env)
            .user(
                UserBuilder::default()
                    .username(image_cfg.user().clone().unwrap_or("root".to_string()))
                    .uid(0u32)
                    .gid(0u32)
                    .build()?,
            )
            .build()?;

        let root = RootBuilder::default()
            .path(ROOTFS_PATH)
            .readonly(false)
            .build()?;

        let linux = LinuxBuilder::default()
            .namespaces(vec![
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Mount)
                    .build()?,
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Pid)
                    .build()?,
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Ipc)
                    .build()?,
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Uts)
                    .build()?,
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path(netns_path)
                    .build()?,
            ])
            .build()?;

        let spec = SpecBuilder::default()
            .version(OCI_RUNTIME_SPEC_VER)
            .process(process)
            .root(root)
            .linux(linux)
            .build()?;

        Ok(spec)
    }
}

fn normalize_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}
