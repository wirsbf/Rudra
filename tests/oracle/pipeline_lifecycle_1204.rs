use rudra::action::Action;
use rudra::address::Address;
use rudra::coreaction::{ActionStart, ActionStop};
use rudra::funcdata::Funcdata;
use rudra::space::AddressSpace;

fn dump_state(label: &str, fd: &Funcdata, heritage_info_built: bool) {
    let register_passes = heritage_info_built
        .then(|| fd.heritage.num_heritage_passes(AddressSpace::Register).to_string())
        .unwrap_or_else(|| "na".to_string());
    let stack_passes = heritage_info_built
        .then(|| fd.heritage.num_heritage_passes(AddressSpace::Stack).to_string())
        .unwrap_or_else(|| "na".to_string());
    println!(
        "{label}:started={},complete={},alive={},dead={},ops={},varnodes={},blocks={},calls={},heritage={},register_passes={},stack_passes={},input_locked={},output_locked={},model_locked={}",
        u8::from(fd.is_proc_started()),
        u8::from(fd.is_proc_complete()),
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        fd.obank.optree.len(),
        fd.vbank.num_varnodes(),
        fd.bblocks.get_size(),
        fd.num_calls(),
        fd.heritage.get_pass(),
        register_passes,
        stack_passes,
        u8::from(fd.funcp.is_input_locked()),
        u8::from(fd.funcp.is_output_locked()),
        u8::from(fd.funcp.is_model_locked()),
    );
}

fn main() {
    // Match the Funcdata identity produced by the locked BfdArchitecture.
    // The ELF symbol size is 0x4a, but Funcdata::getSize() is initially zero.
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    dump_state("before_start", &fd, false);
    let start_return = ActionStart::new()
        .apply(&mut fd)
        .expect("ActionStart lifecycle");
    println!("start_return={start_return}");
    dump_state("after_start", &fd, true);

    let pending = fd.new_op(0, fd.baseaddr);
    fd.obank.mark_dead(pending);
    println!("stop_dead_before={}", fd.obank.deadlist.len());
    let stop_return = ActionStop::new()
        .apply(&mut fd)
        .expect("ActionStop lifecycle");
    println!("stop_return={stop_return}");
    dump_state("after_stop", &fd, true);
}
