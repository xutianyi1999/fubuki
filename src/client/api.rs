pub async fn api_server_start() {
    // let node_table_self = warp::path!("nodeTable"/ "self")
    //     .map(|| "node_table_self");
    //
    // let node_table_all = warp::path!("nodeTable" / "all")
    //     .map(|| "node_table_all");
    //
    // // nodeTable/10.0.0.1/self
    // let node_table_segment_self = warp::path!("nodeTable" / Ipv4Addr / "self")
    //     .map(|segment: Ipv4Addr| {
    //         "node_table_segment_self"
    //     });
    //
    // // nodeTable/10.0.0.1/all
    // let node_table_segment_all = warp::path!("nodeTable" / Ipv4Addr / "all")
    //     .map(|segment: Ipv4Addr| {
    //         "node_table_segment_all"
    //     });
    //
    // // nodeTable/10.0.0.1/11
    // let node_table_segment_specific = warp::path!("nodeTable" / Ipv4Addr / NodeId)
    //     .map(|a, b| "node_table_segment_specific");
    //
    // let routes = warp::get().and(
    //     node_table_self
    //         .or(node_table_all)
    //         .or(node_table_segment_self)
    //         .or(node_table_segment_all)
    //         .or(node_table_segment_specific)
    // );
    // warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}