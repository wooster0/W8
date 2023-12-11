const std = @import("std");
const builtin = @import("builtin");
const terminal = @import("terminal.zig");

const Instruction = packed struct(u8) {
    tag: Tag,
    argument1: Register,
    argument2: RegisterOrImmediate,

    const Tag = enum(u4) {
        SET,
        LOD,
        STR,

        AND,
        IOR,
        EOR,
        ADD,
        SUB,

        TWS,
        TSW,
        TPW,

        WAI,
        JMP,
        PSH,
        POP,
        DRW,

        fn parse(mnemonic: []const u8) AssemblyError!Tag {
            return std.meta.stringToEnum(Tag, mnemonic) orelse return error.@"UNKNOWN INSTRUCTION";
        }
    };

    const Register = enum(u2) {
        X,
        Y,
        I,
        W,

        fn parse(name: []const u8) AssemblyError!Register {
            if (name.len > 1) return error.@"UNKNOWN REGISTER";
            return switch (name[0]) {
                'X' => .X,
                'Y' => .Y,
                'I' => .I,
                'W' => .W,
                else => return error.@"UNKNOWN REGISTER",
            };
        }
    };

    const RegisterOrImmediate = enum(u2) {
        immediate,
        X,
        Y,
        W,

        fn parse(name: []const u8) AssemblyError!RegisterOrImmediate {
            if (name.len > 1) return error.@"UNKNOWN REGISTER";
            return switch (name[0]) {
                'X' => .X,
                'Y' => .Y,
                'W' => .W,
                else => return error.@"UNKNOWN REGISTER",
            };
        }
    };
};

const Value = union(enum) {
    immediate: u8,
    label_name: []const u8,

    fn parse(string: []const u8) AssemblyError!Value {
        const result = switch (string[0]) {
            '$' => result: {
                var result: u8 = 0;
                for (string[1..]) |digit| {
                    if (digit == '_') continue;
                    result = std.math.mul(u8, result, 16) catch return error.OVERFLOW;
                    result += switch (digit) {
                        '0'...'9' => digit - '0',
                        'A'...'F' => digit - 'A' + 10,
                        else => return error.@"NOT HEXADECIMAL",
                    };
                }
                break :result result;
            },
            '%' => result: {
                var result: u8 = 0;
                for (string[1..]) |digit| {
                    if (digit == '_') continue;
                    result = std.math.mul(u8, result, 2) catch return error.OVERFLOW;
                    result += switch (digit) {
                        '0' => 0,
                        '1' => 1,
                        else => return error.@"NOT BINARY",
                    };
                }
                break :result result;
            },
            '0'...'9' => result: {
                var result: u8 = 0;
                for (string) |digit| {
                    if (digit == '_') continue;
                    result = std.math.mul(u8, result, 10) catch return error.OVERFLOW;
                    result += switch (digit) {
                        '0'...'9' => digit - '0',
                        else => return error.@"NOT DECIMAL",
                    };
                }
                break :result result;
            },
            '\'' => result: {
                if (string.len != 3) return error.@"NOT CHARACTER";
                if (string[2] != '\'') return error.@"NOT CHARACTER";
                break :result string[1] - ' '; // Convert to 6-bit ASCII.
            },
            'A'...'Z' => {
                for (string[1..]) |digit| {
                    switch (digit) {
                        'A'...'Z', '_' => {},
                        else => return error.@"NOT IDENTIFIER",
                    }
                }
                return .{ .label_name = string };
            },
            else => return error.UNKNOWN,
        };
        return .{ .immediate = result };
    }
};

/// Compiles the given source code. Compilation means preprocessing and assembly.
fn compile(allocator: std.mem.Allocator, name: []const u8, source: []const u8) ExitError![256]u8 {
    try verify_source_character_set(source);

    const preprocessed_source = preprocess(allocator, source) catch |err| {
        switch (err) {
            // TODO: not possible yet
            //std.mem.Allocator.Error
            error.OutOfMemory => terminal.stderr.writer().print("OUT OF MEMORY.\n", .{}) catch {},
            // TODO: not possible yet
            //error.PreprocessError =>
            else => |preprocess_error| {
                terminal.stderr.writer().print("PREPROCESS ERROR: {s}.\n", .{@errorName(preprocess_error)}) catch {};
            },
        }
        return error.exit;
    };
    defer allocator.free(preprocessed_source);

    //std.debug.print("{s}\n", .{preprocessed_source});

    var memory: [256]u8 = undefined;
    // Zero initialization is the most useful to the programmer here because this includes the stack and graphics memory.
    // Otherwise the screen's content would be undefined.
    @memset(&memory, 0);

    assemble(allocator, preprocessed_source, &memory) catch |err| {
        switch (err) {
            // TODO: not possible yet
            //std.mem.Allocator.Error
            error.OutOfMemory => terminal.stderr.writer().print("OUT OF MEMORY.\n", .{}) catch {},
            // TODO: not possible yet
            //error.AssemblyError =>
            else => |assembly_error| {
                terminal.stderr.writer().print(
                    "ASSEMBLY ERROR IN LINE {d}:\n\x1b[30m\x1b[47m{s}\x1b[0m\n{s}: \x1b[30m\x1b[47m{s}\x1b[0m.\n",
                    .{
                        current_line_number,
                        current_line,
                        @errorName(assembly_error),
                        current_token,
                    },
                ) catch {};
            },
        }
        return error.exit;
    };

    //std.debug.print("memory: {any}\n", .{memory});

    std.fs.cwd().writeFile(name, &memory) catch {
        terminal.stderr.writer().print("OUTPUT WRITE FAILED.\n", .{}) catch {};
        return error.exit;
    };

    return memory;
}

/// This is used to simply propagate failure to the main function so that it exits with 1.
/// The actual error has already been reported.
const ExitError = error{exit};

pub fn main() u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.detectLeaks();

    var args = std.process.argsWithAllocator(allocator) catch |err| {
        switch (err) {
            error.OutOfMemory => terminal.stderr.writer().print("OUT OF MEMORY.\n", .{}) catch {},
            else => terminal.stderr.writer().print("UNABLE TO READ INPUT.\n", .{}) catch {},
        }
        return 1;
    };
    defer args.deinit();
    _ = args.skip();
    const file_path = args.next() orelse {
        terminal.stderr.writer().print("NO INPUT GIVEN.\n", .{}) catch {};
        return 1;
    };
    const content = std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize)) catch |err| {
        switch (err) {
            error.OutOfMemory => terminal.stderr.writer().print("OUT OF MEMORY.\n", .{}) catch {},
            else => terminal.stderr.writer().print("UNABLE TO READ INPUT.\n", .{}) catch {},
        }
        return 1;
    };
    defer allocator.free(content);
    const extension = std.fs.path.extension(file_path);
    const name = std.fs.path.stem(file_path);
    // Verify that the name conforms to 6-bit ASCII.
    for (name) |byte| {
        switch (byte) {
            ' '...'_' => {},
            else => {
                terminal.stderr.writer().print("SOURCE NAME CONTAINS INVALID BYTE {d}.\n", .{byte}) catch {};
                return 1;
            },
        }
    }
    const memory = if (std.mem.eql(u8, extension, ".W8")) memory: {
        var memory = compile(allocator, name, content) catch return 1;
        break :memory &memory;
    } else if (content.len == 256) memory: {
        break :memory content[0..256];
    } else {
        terminal.stderr.writer().print("INPUT IS NOT SOURCE CODE OR EXECUTABLE.\n", .{}) catch {};
        return 1;
    };
    return execute(memory);
}

/// Verify that the input assembly source code conforms to 6-bit ASCII, with the exception of the newline character.
fn verify_source_character_set(source: []const u8) ExitError!void {
    var line: usize = 1;
    for (source) |byte| {
        switch (byte) {
            ' '...'_' => {},
            '\n' => line += 1,
            else => {
                terminal.stderr.writer().print("SOURCE CONTAINS INVALID BYTE {d} IN LINE {}.\n", .{ byte, line }) catch {};
                return error.exit;
            },
        }
    }
}

const PreprocessError = error{
    @"MACRO NAME MISMATCH",
    @"DUPLICATE MACRO DEFINITION",
    @"WRONG MACRO PARAMETER INDEX ORDER",
    @"MACRO PARAMETER WITHOUT INDEX",
    @"UNKNOWN MACRO",
    @"MACRO CALL EXPECTED ARGUMENT",
    @"UNTERMINATED MACRO",
};

const Macro = struct {
    /// The content in between two macro names %EXAMPLE% and %EXAMPLE%, referencing the source.
    content: []const u8,
    /// A list of parameters in the format of @0, @1, @2, and so on, referencing the source.
    parameters: []const []const u8,

    fn deinit(macro: Macro, allocator: std.mem.Allocator) void {
        allocator.free(macro.parameters);
    }
};

/// Preprocesses macros and outputs new source code to be assembled.
/// Does not support nested macros.
/// Also takes care of comments.
///
/// A problem that I have to acknowledge with this is that assembly error line numbers will usually be
/// incorrect if an assembly error comes from inside a macro.
/// This and many other problems could be fixed if we wrote a proper tokenizer.
fn preprocess(allocator: std.mem.Allocator, source: []const u8) (PreprocessError || std.mem.Allocator.Error)![]const u8 {
    var macros = std.StringHashMap(Macro).init(allocator);
    defer {
        var values = macros.valueIterator();
        while (values.next()) |macro| {
            macro.deinit(allocator);
        }
        macros.deinit();
    }
    var index: usize = 0;
    var current_macro_name: ?[]const u8 = null;
    var current_macro_start: usize = undefined;
    var output = std.ArrayList(u8).init(allocator);
    preprocess: while (index < source.len) : (index += 1) {
        const character = source[index];
        if (character == '%') {
            // This is possibly a macro definition.
            // Parse the macro's name if this is one and avoid false-positives.
            index += 1;
            const macro_name_start = index;
            while (source[index] != '%') {
                if (index == source.len or source[index] == ' ' or source[index] == '\n') {
                    // Add back to the source what turned out not to be a macro name
                    // and strip any possible comment.
                    const string = source[macro_name_start - 1 .. index + 1];
                    try output.appendSlice(string); //string[0..std.mem.indexOfScalar(u8,string,';') orelse string.len]);
                    continue :preprocess;
                }
                index += 1;
            }
            const macro_name_end = index;
            index += 1;
            const macro_name = source[macro_name_start..macro_name_end];
            // Slice the content in between two macro names by finding two matching ones.
            if (current_macro_name) |previous_macro_name| {
                if (!std.mem.eql(u8, macro_name, previous_macro_name)) {
                    return error.@"MACRO NAME MISMATCH";
                }
                const get_or_put = try macros.getOrPut(macro_name);
                if (get_or_put.found_existing) return error.@"DUPLICATE MACRO DEFINITION";

                // We now have the macro's content that is in between %EXAMPLE% and %EXAMPLE%.
                // Find the parameters designated by at signs followed by a number unique within the macro.
                const content = source[current_macro_start .. index - (macro_name.len + "%%".len)];
                var parameters = std.ArrayList([]const u8).init(allocator);
                var content_index: usize = 0;
                while (content_index < content.len) : (content_index += 1) {
                    if (content[content_index] == '@') {
                        const parameter_start = content_index;
                        content_index += 1;
                        while (content_index < content.len) : (content_index += 1) {
                            switch (content[content_index]) {
                                '0'...'9' => {},
                                else => break,
                            }
                        }
                        const parameter_end = content_index;
                        const parameter = content[parameter_start..parameter_end];
                        if (parameter.len == 1) return error.@"MACRO PARAMETER WITHOUT INDEX";
                        const parameter_index = std.fmt.parseUnsigned(usize, parameter[1..], 10) catch unreachable;
                        if (parameter_index != parameters.items.len) return error.@"WRONG MACRO PARAMETER INDEX ORDER";
                        try parameters.append(parameter);
                    }
                }

                get_or_put.value_ptr.* = .{ .content = content, .parameters = try parameters.toOwnedSlice() };
                current_macro_name = null;
            } else {
                // We might find the other macro name later.
                current_macro_start = index;
                current_macro_name = macro_name;
            }
        } else if (character == '#') {
            // This is possibly a macro call which is going to paste the macro's content here.
            const line_end = if (std.mem.indexOfScalarPos(u8, source, index, '\n')) |newline_index| newline_index else source.len;
            var tokens = std.mem.tokenizeScalar(u8, source[index..line_end], ' ');
            if (tokens.next()) |prefixed_macro_name| {
                const macro_name = prefixed_macro_name[1..];
                const macro = macros.get(macro_name) orelse return error.@"UNKNOWN MACRO";
                // Replace parameters in the macro content with the given arguments.
                var content = macro.content;
                var allocated = false;
                for (macro.parameters) |parameter| {
                    const new_content = try std.mem.replaceOwned(u8, allocator, content, parameter, tokens.next() orelse return error.@"MACRO CALL EXPECTED ARGUMENT");
                    if (allocated) allocator.free(content);
                    allocated = true;
                    content = new_content;
                }
                // Append the content to the output.
                // This copies the bytes instead of taking ownership.
                {
                    // Strip comments.
                    var lines = std.mem.tokenizeScalar(u8, content, '\n');
                    while (lines.next()) |line| {
                        try output.appendSlice(line[0 .. std.mem.indexOfScalar(u8, line, ';') orelse line.len]);
                        try output.append('\n');
                    }
                }
                // And so we still have ownership here and free if we allocated.
                if (allocated) allocator.free(content);
            }
            index = line_end - 1;
        } else if (character == ';') {
            // Ignore comments.
            const line_end = std.mem.indexOfScalarPos(u8, source, index, '\n') orelse source.len;
            index = line_end - 1;
        } else if (character == '"') {
            // Ignore any possible macro syntax inside strings.
            try output.append(character);
            index += 1;
            while (index < source.len) : (index += 1) {
                try output.append(source[index]);
                if (source[index] == '"') {
                    break;
                }
            }
        } else if (current_macro_name == null) {
            // For regular code, append to the output source code.
            try output.append(character);
        } else {
            // We're inside a macro. Do not append.
        }
    }
    if (current_macro_name != null) return error.@"UNTERMINATED MACRO";
    return output.toOwnedSlice();
}

// These are for error diagnostics.
var current_line: []const u8 = undefined;
var current_line_number: usize = 0;
var current_token: []const u8 = undefined;

const AssemblyError = error{
    @"UNKNOWN REGISTER",
    @"UNKNOWN INSTRUCTION",
    @"UNKNOWN LABEL",
    @"NOT HEXADECIMAL",
    @"NOT BINARY",
    @"NOT DECIMAL",
    @"NOT CHARACTER",
    @"NOT IDENTIFIER",
    @"NOT SUPPOSED TO BE HERE",
    OVERFLOW,
    @"LABEL ALREADY EXISTS",
    UNTERMINATED,
    @"MISSING VALUE AFTER",
    @"MISSING REGISTER AFTER",
    @"CANNOT USE I REGISTER",
    UNKNOWN,
};

// This allows assembly such as:
// ```
// JMP EXIT
// EXIT:
// ```
const UnresolvedLabelAddress = struct {
    label_name: []const u8,
    program_index: u8,
    // These are for error diagnostics if the label address cannot be resolved because the label is unknown.
    line: []const u8,
    line_number: usize,
    token: []const u8,
};

/// Scans for values that are, and partly cannot be, part of an instruction.
/// This includes label definitions, strings, and other values.
fn scan_for_other_values(
    line: []const u8,
    label_addresses: *std.StringHashMap(u8),
    unresolved_label_addresses: *std.ArrayList(UnresolvedLabelAddress),
    program_index: *u8,
    output: *[256]u8,
) (std.mem.Allocator.Error || AssemblyError)!void {
    var line_index: usize = 0;
    scan: while (line_index < line.len) : (line_index += 1) {
        switch (line[line_index]) {
            'A'...'Z' => {
                // A label definition.
                const label_name_start = line_index;
                while (line_index < line.len and line[line_index] != ' ') : (line_index += 1) {}
                const label_name_end = line_index;
                const label_name = line[label_name_start..label_name_end];
                if (label_name[label_name.len - 1] == ':') {
                    const get_or_put = try label_addresses.getOrPut(label_name[0 .. label_name.len - 1]);
                    if (get_or_put.found_existing) return error.@"LABEL ALREADY EXISTS";
                    get_or_put.value_ptr.* = program_index.*;
                } else {
                    try unresolved_label_addresses.append(.{
                        .label_name = label_name,
                        .program_index = program_index.*,
                        .line = current_line,
                        .line_number = current_line_number,
                        .token = current_token,
                    });
                    program_index.* += 1;
                }
            },
            '"' => {
                line_index += 1;
                while (line_index < line.len) : (line_index += 1) {
                    if (line[line_index] == '"') {
                        line_index += 1;
                        continue :scan;
                    }
                    output[program_index.*] = line[line_index] - ' '; // Convert to 6-bit ASCII.
                    program_index.* += 1;
                }
                current_token = line;
                return error.UNTERMINATED;
            },
            else => {
                const value_start = line_index;
                while (line_index < line.len and line[line_index] != ' ') : (line_index += 1) {}
                const value_end = line_index;
                const value = line[value_start..value_end];
                if (value.len == 0) return;
                switch (try Value.parse(value)) {
                    .immediate => |immediate| {
                        output[program_index.*] = immediate;
                        program_index.* += 1;
                    },
                    .label_name => unreachable, // Already handled above.
                }
            },
        }
    }
}

fn assemble(allocator: std.mem.Allocator, source: []const u8, output: *[256]u8) (AssemblyError || std.mem.Allocator.Error)!void {
    var index: u8 = 0;
    var label_addresses = std.StringHashMap(u8).init(allocator);
    defer label_addresses.deinit();
    var unresolved_label_addresses = std.ArrayList(UnresolvedLabelAddress).init(allocator);
    defer unresolved_label_addresses.deinit();
    var lines = std.mem.tokenizeScalar(u8, source, '\n');
    while (lines.next()) |line| {
        current_line = line;
        current_line_number += 1;
        var tokens = std.mem.tokenizeScalar(u8, line, ' ');
        const token = tokens.next() orelse continue;
        current_token = token;
        const tag = Instruction.Tag.parse(token) catch {
            try scan_for_other_values(line, &label_addresses, &unresolved_label_addresses, &index, output);
            continue;
        };
        var argument1: Instruction.Register = undefined;
        var argument2: Instruction.RegisterOrImmediate = undefined;
        var maybe_value: ?Value = null;
        switch (tag) {
            .LOD,
            .STR,
            => {
                current_token = tokens.next() orelse return error.@"MISSING REGISTER AFTER";
                argument1 = try Instruction.Register.parse(current_token);
                current_token = tokens.next() orelse return error.@"MISSING VALUE AFTER";
                maybe_value = try Value.parse(current_token);
            },
            .SET, .AND, .IOR, .EOR, .ADD, .SUB => {
                current_token = tokens.next() orelse return error.@"MISSING REGISTER AFTER";
                argument1 = try Instruction.Register.parse(current_token);
                current_token = tokens.next() orelse return error.@"MISSING REGISTER AFTER";
                if (Instruction.RegisterOrImmediate.parse(current_token)) |register| {
                    argument2 = register;
                } else |_| {
                    maybe_value = try Value.parse(current_token);
                    argument2 = .immediate;
                }
            },
            .PSH,
            .POP,
            => {
                current_token = tokens.next() orelse return error.@"MISSING REGISTER AFTER";
                argument1 = try Instruction.Register.parse(current_token);
            },
            .TWS,
            .TSW,
            .DRW,
            .TPW,
            => {},
            .WAI => {
                current_token = tokens.next() orelse return error.@"MISSING VALUE AFTER";
                maybe_value = try Value.parse(current_token);
            },
            .JMP => {
                current_token = tokens.next() orelse return error.@"MISSING VALUE AFTER";
                if (Instruction.RegisterOrImmediate.parse(current_token)) |register| {
                    argument2 = register;
                } else |_| {
                    maybe_value = try Value.parse(current_token);
                    argument2 = .immediate;
                }
            },
        }
        if (tokens.next()) |unexpected_token| {
            current_token = unexpected_token;
            return error.@"NOT SUPPOSED TO BE HERE";
        }
        output[index] = @bitCast(Instruction{ .tag = tag, .argument1 = argument1, .argument2 = argument2 });
        index += 1;
        if (maybe_value) |value| {
            switch (value) {
                .immediate => |immediate| output[index] = immediate,
                .label_name => |label_name| {
                    try unresolved_label_addresses.append(.{
                        .label_name = label_name,
                        .program_index = index,
                        .line = current_line,
                        .line_number = current_line_number,
                        .token = current_token,
                    });
                },
            }
            index += 1;
        }
    }
    for (unresolved_label_addresses.items) |unresolved_label_address| {
        output[unresolved_label_address.program_index] = label_addresses.get(unresolved_label_address.label_name) orelse {
            current_line = unresolved_label_address.line;
            current_line_number = unresolved_label_address.line_number;
            current_token = unresolved_label_address.token;
            return error.@"UNKNOWN LABEL";
        };
    }
}

var drawn_system = false;

fn draw_system(memory: *[256]u8, s: Status) void {
    const screen_width = 8;
    const screen_height = 8;

    const Cell = packed struct(u8) {
        character: u6,
        color: enum(u2) {
            white,
            red,
            green,
            blue,
        },
    };

    terminal.cursor.hide();

    if (drawn_system) {
        // We need to do this so that we draw the system
        // at the same position again next time.
        terminal.cursor.move_up(screen_height + 3);
    }
    drawn_system = true;

    // Screen
    terminal.write("╔");
    for (0..screen_width * 2) |_| {
        terminal.write("═");
    }
    terminal.write("╗\r\n");
    const graphics = memory[0xb0..0xf0];
    terminal.write("║");
    for (graphics, 0..) |cell_byte, index| {
        const cell: Cell = @bitCast(cell_byte);
        if (index != 0 and index % screen_width == 0) {
            terminal.write("\x1b[0m║\r\n║");
        }
        switch (s.color) {
            .foreground => {
                terminal.write("\x1b[40m"); // Black background.
                switch (cell.color) {
                    .white => terminal.write("\x1b[37m"),
                    .red => terminal.write("\x1b[31m"),
                    .green => terminal.write("\x1b[32m"),
                    .blue => terminal.write("\x1b[34m"),
                }
            },
            .background => {
                terminal.write("\x1b[30m"); // Black foreground.
                switch (cell.color) {
                    .white => terminal.write("\x1b[47m"),
                    .red => terminal.write("\x1b[41m"),
                    .green => terminal.write("\x1b[42m"),
                    .blue => terminal.write("\x1b[44m"),
                }
            },
        }
        if (cell.character == 0)
            terminal.write("  ")
        else
            // The character is in 6-bit ASCII.
            // For output, convert to full-width 7-bit ASCII.
            terminal.print("{u}", .{@as(u21, cell.character) + 0xFF00});
    }
    terminal.write("\x1b[0m║\r\n╚");
    for (0..screen_width * 2) |_| {
        terminal.write("═");
    }
    terminal.write("╝\r\n");

    // Lights
    terminal.print("   \x1b[31m{s}   \x1b[32m{s}   \x1b[34m{s}\x1b[0m\n", .{
        if (s.red) "▓▓" else "░░",
        if (s.green) "▓▓" else "░░",
        if (s.blue) "▓▓" else "░░",
    });

    terminal.cursor.show();

    terminal.flush();
}

const Status = packed struct(u8) {
    unused: u3 = undefined,
    accept_input: bool = false,
    color: enum(u1) {
        foreground,
        background,
    } = .foreground,
    blue: bool = false,
    green: bool = false,
    red: bool = false,
};

fn execute(memory: *[256]u8) u8 {
    // Zero initialization is the most useful to the programmer here and is consistent with PC and SP also being zero-initialized.
    // Otherwise, zero initialization instructions would waste space.
    var x: u8 = 0;
    var y: u8 = 0;
    var i: u8 = 0;
    var w: u8 = 0;
    var s: Status = .{};
    var pc: u8 = 0;
    var sp: u4 = 0;

    const can_draw_system = terminal.stdout.supportsAnsiEscapeCodes();

    while (pc < memory.len - 1) {
        //if (pc >= 0xb0) {
        //    std.debug.print("about to execute graphics or stack memory: pc=0x{x} ({c}); exiting\n", .{ pc, pc });
        //    break;
        //}
        const instruction: Instruction = @bitCast(memory[pc]);
        switch (instruction.tag) {
            .LOD => {
                pc += 1;
                const address = memory[pc];
                switch (instruction.argument1) {
                    .X => x = memory[address +% i],
                    .Y => y = memory[address +% i],
                    .I => i = memory[address +% i],
                    .W => w = memory[address +% i],
                }
            },
            .STR => {
                pc += 1;
                const address = memory[pc];
                switch (instruction.argument1) {
                    .X => memory[address +% i] = x,
                    .Y => memory[address +% i] = y,
                    .I => memory[address +% i] = i,
                    .W => memory[address +% i] = w,
                }
            },

            .SET => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x = value,
                    .Y => y = value,
                    .I => i = value,
                    .W => w = value,
                }
            },
            .AND => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x &= value,
                    .Y => y &= value,
                    .I => i &= value,
                    .W => w &= value,
                }
            },
            .IOR => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x |= value,
                    .Y => y |= value,
                    .I => i |= value,
                    .W => w |= value,
                }
            },
            .EOR => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x ^= value,
                    .Y => y ^= value,
                    .I => i ^= value,
                    .W => w ^= value,
                }
            },
            .ADD => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x +%= value,
                    .Y => y +%= value,
                    .I => i +%= value,
                    .W => w +%= value,
                }
            },
            .SUB => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                switch (instruction.argument1) {
                    .X => x -%= value,
                    .Y => y -%= value,
                    .I => i -%= value,
                    .W => w -%= value,
                }
            },

            .TWS => {
                s = @bitCast(w);
                if (can_draw_system) {
                    draw_system(memory, s);
                }
            },
            .TSW => w = @bitCast(s),

            .DRW => {
                const graphics = memory[0xb0..0xf0];
                graphics[@as(u3, @truncate(x)) + @as(u8, @as(u3, @truncate(y))) * 8] = w;
                if (can_draw_system) {
                    draw_system(memory, s);
                } else {
                    // The character is in 6-bit ASCII.
                    // For output, convert to 7-bit ASCII.
                    terminal.stdout.writer().writeByte(w + ' ') catch {};
                }
            },

            .WAI => {
                if (s.accept_input) {
                    terminal.make_non_canonical();
                    defer terminal.make_canonical();
                    var file_descriptors = [1]std.os.pollfd{.{ .fd = terminal.stdin.handle, .events = std.os.POLL.IN, .revents = 0 }};
                    const result = std.os.poll(&file_descriptors, if (w == 0) -1 else 200 * @as(i32, w)) catch result: {
                        std.time.sleep(std.time.ns_per_ms * 200 * @as(u64, w));
                        break :result 0;
                    };
                    switch (result) {
                        0 => {
                            // The poll timed out.
                            // This means we waited the duration specified by W.
                        },
                        1 => {
                            // We have input to read.
                            _ = terminal.stdin.read(@as(*[1]u8, @ptrCast(&i))) catch {};
                            // Convert to 6-bit ASCII.
                            i = std.ascii.toUpper(i);
                            i = switch (i) {
                                ' '...'_' => i,
                                else => ' ',
                            };
                            i -= ' ';
                        },
                        else => unreachable,
                    }
                } else {
                    std.time.sleep(std.time.ns_per_ms * 200 * @as(u64, w));
                }
                pc += 1;
                const address = memory[pc];
                w = pc + 1; // Return address to continue at the instruction after this one.
                pc = address;
                continue;
            },
            .JMP => {
                const value = switch (instruction.argument2) {
                    .immediate => value: {
                        pc += 1;
                        break :value memory[pc];
                    },
                    .X => x,
                    .Y => y,
                    .W => w,
                };
                if (w != 0) {
                    pc = value;
                    continue;
                } else {
                    // Skip the jump.
                }
            },
            .PSH => {
                // Grow upwards to 0xf0 starting at 0xff.
                const value = switch (instruction.argument1) {
                    .X => x,
                    .Y => y,
                    .I => i,
                    .W => w,
                };
                memory[0xff - @as(u8, sp)] = value;
                sp +%= 1;
            },
            .POP => {
                // Shrink downwards to 0xff starting at 0xf0.
                sp -%= 1;
                const value = memory[0xff - @as(u8, sp)];
                switch (instruction.argument1) {
                    .X => x = value,
                    .Y => y = value,
                    .I => i = value,
                    .W => w = value,
                }
            },
            .TPW => w = pc,
        }
        pc += 1;
    }

    return w;
}
