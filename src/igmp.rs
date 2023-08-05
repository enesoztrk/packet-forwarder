
#[derive(Debug)]
#[derive(Default)]
pub struct igmpv3_grec {
	pub grec_type:u8,
	pub grec_auxwords:u8,
	pub grec_nsrcs:[u8;2],
	pub grec_mca:[u8;4],
	pub grec_src:[u8;4]
}

#[derive(Debug)]
#[derive(Default)]
pub struct igmpv3_report {
	pub type_igmp:u8,
	pub resv1:u8,
	pub csum:[u8;2],
	pub resv2:[u8;2],
	pub ngrec:[u8;2],
	pub grec:igmpv3_grec
}