const loader = @import("loader.zig");
const fdl_resolve = @import("fdl_resolve.zig");

pub const Context = fdl_resolve.Context;
pub const RTLD_LAZY = fdl_resolve.RTLD_LAZY;
pub const RTLD_NOW = fdl_resolve.RTLD_NOW;
pub const Entry = loader.Loader;
