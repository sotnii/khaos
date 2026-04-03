use std::io;
use std::string::FromUtf8Error;
use std::process::Command;
use thiserror::Error;
use crate::net::ip_cmd::IpCmdError::{CmdFailed, ErrOutput, InvalidOutput};

#[derive(Debug, Error)]
pub enum IpCmdError {
    #[error("ip command returned error output: {0}")] ErrOutput(String),
    #[error("ip command failed to run")]
    CmdFailed(#[source] io::Error),
    #[error("ip command returned non-utf8 stdout")]
    InvalidOutput(#[source] FromUtf8Error),
}

pub struct IpCmd {}

impl IpCmd {
    pub fn get_if_status(name: impl Into<String>) -> Result<(bool, bool), IpCmdError> {
        let name = name.into();
        match IpCmd::cmd(["link", "show", name.as_str()]) {
            Err(e) => match e {
                ErrOutput(_) => Ok((false, false)),
                e => Err(e),
            }
            Ok(v) => Ok((true, v.contains("state UP"))),
        }
    }
    
    pub fn add_bridge_veth(name: impl Into<String>) -> Result<(), IpCmdError> {
        let name = name.into();
        IpCmd::cmd(["link", "add", name.as_str(), "type", "bridge"])?;
        Ok(())
    }
    
    pub fn bring_veth_up(name: impl Into<String>) -> Result<(), IpCmdError> {
        let name = name.into();
        IpCmd::cmd(["link", "set", name.as_str(), "up"])?;
        Ok(())
    }
    
    pub fn bring_ns_veth_up(ns: impl Into<String>, name: impl Into<String>) -> Result<(), IpCmdError> {
        let ns = ns.into();
        let name = name.into();
        IpCmd::ns_exec(ns.as_str(), ["ip", "link", "set", name.as_str(), "up"])?;
        Ok(())
    }
    
    pub fn add_ns(name: impl Into<String>) -> Result<(), IpCmdError> {
        let name = name.into();
        IpCmd::netns(["add", name.as_str()])?;
        Ok(())
    }

    pub fn del_ns(name: impl Into<String>) -> Result<(), IpCmdError> {
        let name = name.into();
        IpCmd::netns(["del", name.as_str()])?;
        Ok(())
    }

    pub fn add_veth_peer(veth: impl Into<String>, peer: impl Into<String>) -> Result<(), IpCmdError> {
        let veth = veth.into();
        let peer = peer.into();
        IpCmd::cmd([
            "link",
            "add",
            veth.as_str(),
            "type",
            "veth",
            "peer",
            "name",
            peer.as_str(),
        ])?;
        Ok(())
    }

    pub fn move_veth_to_ns(veth: impl Into<String>, ns: impl Into<String>) -> Result<(), IpCmdError> {
        let veth = veth.into();
        let ns = ns.into();
        IpCmd::cmd(["link", "set", veth.as_str(), "netns", ns.as_str()])?;
        Ok(())
    }

    pub fn set_veth_master(veth: impl Into<String>, master: impl Into<String>) -> Result<(), IpCmdError> {
        let veth = veth.into();
        let master = master.into();
        IpCmd::cmd(["link", "set", veth.as_str(), "master", master.as_str()])?;
        Ok(())
    }
    
    fn netns<'a, I>(args: I) -> Result<String, IpCmdError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        IpCmd::cmd(["netns"].into_iter().chain(args))
    }

    // Runs `ip netns exec <ns> <args>`
    fn ns_exec<'a, I>(ns: &'a str, args: I) -> Result<String, IpCmdError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        IpCmd::cmd(["netns", "exec", ns].into_iter().chain(args))
    }
    
    fn cmd<'a, I>(args: I) -> Result<String, IpCmdError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let res = Command::new("ip").args(args).output();
        match res {
            Ok(output) => {
                if !output.status.success() {
                    let reason = String::from_utf8_lossy(&output.stderr);
                    return Err(ErrOutput(reason.to_string()));
                }
                String::from_utf8(output.stdout).map_err(InvalidOutput)
            } ,
            Err(e) => Err(CmdFailed(e)),
        }
    }
}
