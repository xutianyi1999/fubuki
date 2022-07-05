use std::net::IpAddr;
use std::pin::pin;

use anyhow::Result;
use ipnet::Ipv4Net;
use net_route::{Handle, Route};
use futures_util::stream::StreamExt;

use crate::common::net::protocol::VirtualAddr;

pub struct RouteHandle {
    handle: Handle,
    routes: Vec<Route>,
    rt: tokio::runtime::Handle,
    is_sync: bool
}

impl RouteHandle {
    // cidr, gateway, ifindex
    pub fn new(input: &[(Ipv4Net, VirtualAddr, u32)]) -> Result<Self> {
        let mut routes = Vec::new();

        for (cidr, gateway, if_index) in input {
            let route = Route::new(IpAddr::V4(cidr.network()), cidr.prefix_len())
                .with_gateway(IpAddr::V4(*gateway))
                .with_ifindex(*if_index);

            routes.push(route);
        }

        let handle = Handle::new()?;
        let stream = handle.route_listen_stream();

        tokio::spawn(async move {
            let mut stream = pin!(stream);

            while let Some(v) = stream.next().await {
                info!("route change: {:?}", v)
            }
        });

        let this = RouteHandle {
            handle,
            routes,
            rt: tokio::runtime::Handle::current(),
            is_sync: false
        };
        Ok(this)
    }

    pub async fn sync(&mut self) -> Result<()> {
        for x in &self.routes {
            self.handle.add(x).await?;
        }

        self.is_sync = true;
        Ok(())
    }

    pub async fn clear(&mut self) -> Result<()> {
        if !self.is_sync {
            return Ok(())
        }

        for x in &self.routes {
            self.handle.delete(x).await?;
        }

        self.is_sync = false;
        Ok(())
    }
}

impl Drop for RouteHandle {
    fn drop(&mut self) {
        let rt= self.rt.clone();

        if let Err(e) = rt.block_on(self.clear()) {
            error!("delete route failure: {}", e)
        }
    }
}