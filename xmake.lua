target("crypto--")
    set_kind("binary")
    add_files("src/*.cpp") 
    add_headerfiles("include/*.h")
    add_packages("lib/*.lib")