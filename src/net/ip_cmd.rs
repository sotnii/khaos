use std::io;
use std::process::Command;
use thiserror::Error;
use crate::net::ip_cmd::IpCmdError::{CmdFailed, ErrOutput};

#[derive(Debug, Error)]
pub enum IpCmdError {
    #[error("ip command returned error output: {0}")] ErrOutput(String),
    #[error("ip command failed to run")]
    CmdFailed(#[source] io::Error),
}

pub struct IpCmd {}

impl IpCmd {
    pub fn get_if_status(name: impl Into<String>) -> Result<(bool, bool), IpCmdError> {
        match IpCmd::cmd(vec!["link", "show", &name.into()]) {
            Err(e) => match e {
                ErrOutput(_) => Ok((false, false)),
                e => Err(e),
            }
            Ok(v) => Ok((true, v.contains("state UP"))),
        }
    }
    
    pub fn add_bridge_veth(name: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::cmd(vec!["link", "add", &name.into(), "type", "bridge"])?;
        Ok(())
    }
    
    pub fn bring_veth_up(name: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::cmd(vec!["link", "set", &name.into(), "up"])?;
        Ok(())
    }
    
    pub fn bring_ns_veth_up(ns: impl Into<String>, name: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::ns_exec(&ns.into(), vec!["ip", "link", "set", &name.into(), "up"])?;
        Ok(())
    }
    
    pub fn add_ns(name: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::netns(vec!["add", &name.into()])?;
        Ok(())
    }

    pub fn del_ns(name: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::netns(vec!["del", &name.into()])?;
        Ok(())
    }

    pub fn add_veth_peer(veth: impl Into<String>, peer: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::cmd(vec!["link", "add", &veth.into(), "type", "veth", "peer", "name", &peer.into()])?;
        Ok(())
    }

    pub fn move_veth_to_ns(veth: impl Into<String>, ns: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::cmd(vec!["link", "set", &veth.into(), "netns", &ns.into()])?;
        Ok(())
    }

    pub fn set_veth_master(veth: impl Into<String>, master: impl Into<String>) -> Result<(), IpCmdError> {
        IpCmd::cmd(vec!["link", "set", &veth.into(), "master", &master.into()])?;
        Ok(())
    }
    
    fn netns(args : Vec<&str>) -> Result<String, IpCmdError> {
        let mut netns = vec!["netns"];
        netns.extend(args);
        IpCmd::cmd(netns)
    }

    // Runs `ip netns exec <ns> <args>`
    fn ns_exec(ns: &str, args: Vec<&str>) -> Result<String, IpCmdError> {
        let mut cmd = vec!["netns", "exec", &ns];
        cmd.extend(args);
        IpCmd::cmd(cmd)
    }
    
    // TODO:fix unnecessary heap allocation with vec
    //  where
    //      I: IntoIterator<Item = S>,
    //      S: AsRef<str>,
    fn cmd(args: Vec<&str>) -> Result<String, IpCmdError> {
        let res = Command::new("ip").args(&args).output();
        match res {
            Ok(output) => {
                if !output.status.success() {
                    let reason = String::from_utf8_lossy(&output.stderr);
                    return Err(ErrOutput(reason.to_string()));
                }
                // TODO: Unwrapping is not cool
                Ok(String::from_utf8(output.stdout).unwrap())
            } ,
            Err(e) => Err(CmdFailed(e)),
        }
    }
}

