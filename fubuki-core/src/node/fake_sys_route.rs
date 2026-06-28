use anyhow::Result;

pub struct Route {}

pub struct SystemRouteHandle {
}

impl SystemRouteHandle {
    pub fn new() -> Result<Self> {
        Ok(SystemRouteHandle{})
    }

    pub async fn add(&mut self, _routes: &[Route]) -> Result<()> {
        Ok(())
    }

    #[allow(unused)]
    pub async fn clear(&mut self) -> Result<()> {
        Ok(())
    }
}