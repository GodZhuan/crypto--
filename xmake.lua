add_rules("mode.debug", "mode.release")
add_rules("plugin.compile_commands.autoupdate", {outputdir = ".vscode"})

set_languages("c++23")

target("crypto--")
    set_kind("binary")
    add_files("src/*.cpp") 
    add_headerfiles("include/*.h")
    add_links("libtommath.a")
    set_toolchains("llvm")
